package ops

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"np2auto/internal/runner"
	"np2auto/internal/validate"
)

// La aplicación solo edita su propio bloque de haproxy.cfg, delimitado por
// estas marcas. El resto del archivo (global, defaults y lo que el usuario
// haya escrito a mano) no se toca.
const (
	lbBegin    = "# >>> NP2: balanceador gestionado por la consola de automatización. No edite este bloque a mano."
	lbEnd      = "# <<< NP2"
	lbCfg      = "/etc/haproxy/haproxy.cfg"
	lbStatPort = 8404 // estadísticas solo en 127.0.0.1, para leer el estado de los servidores
)

// Algoritmos de balanceo que ofrece la interfaz.
var lbAlgorithms = map[string]string{
	"roundrobin": "por turnos (roundrobin)",
	"leastconn":  "menos conexiones (leastconn)",
	"source":     "según la IP del cliente (source)",
}

// LBServer es un servidor del backend.
type LBServer struct {
	Name string
	Addr string
	Port int
}

// LBConfig es el contenido del bloque de la aplicación.
type LBConfig struct {
	FrontPort int
	Balance   string
	Servers   []LBServer
}

func defaultLB() LBConfig { return LBConfig{FrontPort: 80, Balance: "roundrobin"} }

// Render arma el bloque para haproxy.cfg. Cada respuesta lleva la cabecera
// X-Servidor con el nombre del servidor que la atendió: así se ve el
// balanceo en las pruebas.
func (c LBConfig) Render() string {
	var b strings.Builder
	w := func(s string) { b.WriteString(s + "\n") }
	w(lbBegin)
	w("frontend np2_balanceador")
	w(fmt.Sprintf("    bind *:%d", c.FrontPort))
	w("    mode http")
	w("    default_backend np2_servidores")
	w("")
	w("backend np2_servidores")
	w("    mode http")
	w("    balance " + c.Balance)
	w("    http-response set-header X-Servidor %[srv_name]")
	for _, s := range c.Servers {
		w(fmt.Sprintf("    server %s %s:%d check", s.Name, hostPort(s.Addr), s.Port))
	}
	w("")
	w("listen np2_estadisticas")
	w(fmt.Sprintf("    bind 127.0.0.1:%d", lbStatPort))
	w("    mode http")
	w("    stats enable")
	w("    stats uri /")
	w("    stats refresh 5s")
	w(lbEnd)
	return b.String()
}

// hostPort pone corchetes a una IPv6 (server x [::1]:80).
func hostPort(addr string) string {
	if strings.Contains(addr, ":") {
		return "[" + addr + "]"
	}
	return addr
}

var (
	reLBBind   = regexp.MustCompile(`^\s*bind \*:(\d+)\s*$`)
	reLBBal    = regexp.MustCompile(`^\s*balance (\S+)\s*$`)
	reLBServer = regexp.MustCompile(`^\s*server (\S+) \[?([^\]\s]+?)\]?:(\d+) check\s*$`)
)

// splitLB separa el archivo en lo que hay antes del bloque, el bloque y lo
// que hay después. found=false si el bloque no existe.
func splitLB(cfg string) (before, block, after string, found bool, err error) {
	i := strings.Index(cfg, lbBegin)
	if i < 0 {
		return cfg, "", "", false, nil
	}
	j := strings.Index(cfg[i:], lbEnd)
	if j < 0 {
		return "", "", "", false, errors.New("el bloque de la aplicación en haproxy.cfg está incompleto (falta la marca final): revíselo a mano")
	}
	end := i + j + len(lbEnd)
	if end < len(cfg) && cfg[end] == '\n' {
		end++
	}
	return cfg[:i], cfg[i:end], cfg[end:], true, nil
}

// parseLB lee el bloque de la aplicación (si existe).
func parseLB(cfg string) (LBConfig, bool, error) {
	_, block, _, found, err := splitLB(cfg)
	if err != nil || !found {
		return defaultLB(), false, err
	}
	c := LBConfig{}
	for _, l := range strings.Split(block, "\n") {
		if m := reLBBind.FindStringSubmatch(l); m != nil {
			c.FrontPort, _ = strconv.Atoi(m[1])
		} else if m := reLBBal.FindStringSubmatch(l); m != nil {
			c.Balance = m[1]
		} else if m := reLBServer.FindStringSubmatch(l); m != nil {
			p, _ := strconv.Atoi(m[3])
			c.Servers = append(c.Servers, LBServer{Name: m[1], Addr: m[2], Port: p})
		}
	}
	if c.FrontPort == 0 || c.Balance == "" {
		return c, true, errors.New("no se pudo leer el bloque de la aplicación en haproxy.cfg: revíselo a mano")
	}
	return c, true, nil
}

// withLB reemplaza (o agrega al final) el bloque de la aplicación.
func withLB(cfg string, c LBConfig) (string, error) {
	before, _, after, _, err := splitLB(cfg)
	if err != nil {
		return "", err
	}
	if before != "" && !strings.HasSuffix(before, "\n") {
		before += "\n"
	}
	if before != "" && !strings.HasSuffix(before, "\n\n") {
		before += "\n"
	}
	return before + c.Render() + after, nil
}

var reAnyBind = regexp.MustCompile(`^\s*bind\s+(\S+)`)

// portInUse indica si otra sección de haproxy.cfg (fuera del bloque) ya
// escucha en ese puerto: HAProxy no arrancaría.
func portInUse(cfg string, port int) bool {
	before, _, after, _, _ := splitLB(cfg)
	suffix := ":" + strconv.Itoa(port)
	for _, l := range strings.Split(before+after, "\n") {
		if m := reAnyBind.FindStringSubmatch(l); m != nil && strings.HasSuffix(strings.Split(m[1], ",")[0], suffix) {
			return true
		}
	}
	return false
}

// LBAddInput son los datos del formulario para agregar un servidor.
type LBAddInput struct {
	Name      string
	Addr      string
	Port      int
	FrontPort int    // puerto del balanceador (0 = no cambiar)
	Balance   string // algoritmo ("" = no cambiar)
}

// Validate comprueba los datos.
func (in LBAddInput) Validate() error {
	if err := validate.ServerName(in.Name); err != nil {
		return err
	}
	if err := validate.Address(in.Addr); err != nil {
		return err
	}
	if in.Port < 1 || in.Port > 65535 {
		return fmt.Errorf("puerto del servidor inválido: %d", in.Port)
	}
	if in.FrontPort != 0 && (in.FrontPort < 1 || in.FrontPort > 65535 || in.FrontPort == lbStatPort) {
		return fmt.Errorf("puerto del balanceador inválido: %d", in.FrontPort)
	}
	if _, ok := lbAlgorithms[in.Balance]; in.Balance != "" && !ok {
		return fmt.Errorf("algoritmo de balanceo desconocido %q", in.Balance)
	}
	return nil
}

// lbRead lee haproxy.cfg y su huella (para no pisar cambios hechos entre la
// lectura y la escritura).
func (o *opRun) lbRead() (cfg, hash string, ok bool) {
	ok = o.step("Leer la configuración de HAProxy", func() (string, string, error) {
		r, err := o.remote("leer", `
command -v haproxy >/dev/null || { echo "HAProxy no está instalado en esta VM: instálelo en «Instalar y eliminar aplicaciones» (paquete haproxy)" >&2; exit 1; }
[ -f `+lbCfg+` ] || { echo "no existe `+lbCfg+`" >&2; exit 1; }
echo "$(haproxy -v | head -1)"
cat `+lbCfg+`
`, time.Minute)
		if err != nil {
			return "", joinTech(r), err
		}
		version, rest, _ := strings.Cut(r.Stdout, "\n")
		cfg = rest
		sum := sha256.Sum256([]byte(cfg))
		hash = hex.EncodeToString(sum[:])
		c, found, perr := parseLB(cfg)
		if perr != nil {
			return "", "", perr
		}
		d := version + ". "
		if !found {
			d += "Todavía no hay balanceador configurado por esta aplicación: se creará el frontend y el backend."
		} else {
			d += fmt.Sprintf("Balanceador en el puerto %d, %s, %d servidores en el backend%s.", c.FrontPort, c.Balance, len(c.Servers), serverList(c.Servers))
		}
		return d, "", nil
	})
	return
}

func serverList(s []LBServer) string {
	if len(s) == 0 {
		return ""
	}
	names := make([]string, len(s))
	for i, x := range s {
		names[i] = fmt.Sprintf("%s (%s:%d)", x.Name, x.Addr, x.Port)
	}
	return ": " + strings.Join(names, ", ")
}

// lbApply valida la configuración nueva con haproxy -c, la instala (con
// copia del archivo anterior) y recarga HAProxy. Si HAProxy no queda activo
// se restaura la copia.
func (o *opRun) lbApply(cfg, hash string) bool {
	return o.step("Validar la configuración (haproxy -c) y recargar HAProxy", func() (string, string, error) {
		r, err := o.remote("aplicar", `
f=`+lbCfg+`
[ "$(sha256sum "$f" | cut -d' ' -f1)" = `+runner.Quote(hash)+` ] || { echo "haproxy.cfg cambió mientras se editaba: vuelva a intentarlo" >&2; exit 1; }
tmp=$(mktemp /etc/haproxy/.np2-XXXXXX.cfg)
printf '%s' `+runner.Quote(cfg)+` > "$tmp"
if ! out=$(haproxy -c -f "$tmp" 2>&1); then
  echo "$out" >&2
  rm -f "$tmp"
  echo "haproxy -c rechazó la configuración nueva; no se cambió nada" >&2
  exit 1
fi
echo "$out" | tail -1
cp -p "$f" "$f.np2-prev"
chmod 644 "$tmp"
mv "$tmp" "$f"
if systemctl is-active --quiet haproxy; then systemctl reload haproxy; else systemctl enable --now haproxy 2>&1; fi
sleep 1
if ! systemctl is-active --quiet haproxy; then
  cp -p "$f.np2-prev" "$f"
  systemctl restart haproxy || true
  echo "HAProxy no quedó activo con la configuración nueva; se restauró la anterior" >&2
  journalctl -u haproxy -n 15 --no-pager >&2 || true
  exit 1
fi
echo "configuración aplicada; copia anterior en $f.np2-prev"
`, 2*time.Minute)
		return firstLines(r.Stdout, 2), joinTech(r), err
	})
}

// lbStatus lee las estadísticas de HAProxy (CSV) y deja la tabla de
// servidores en la vista previa. Devuelve el estado por servidor.
func (o *opRun) lbStatus(name string) (map[string]string, bool) {
	states := map[string]string{}
	ok := o.step(name, func() (string, string, error) {
		r, err := o.remote("estado", `
sleep 2
timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/`+strconv.Itoa(lbStatPort)+` && printf "GET /;csv HTTP/1.0\r\nHost: localhost\r\n\r\n" >&3 && cat <&3' \
  || { echo "no se pudieron leer las estadísticas de HAProxy en 127.0.0.1:`+strconv.Itoa(lbStatPort)+`" >&2; exit 1; }
`, time.Minute)
		if err != nil {
			return "", joinTech(r), err
		}
		table, st := parseStatsCSV(r.Stdout)
		states = st
		o.res.Preview = table
		up := 0
		for _, s := range st {
			if strings.HasPrefix(s, "UP") {
				up++
			}
		}
		return fmt.Sprintf("%d de %d servidores disponibles (UP)", up, len(st)), "", nil
	})
	return states, ok
}

// parseStatsCSV toma la respuesta HTTP con el CSV de estadísticas y devuelve
// una tabla legible de los servidores del backend y su estado.
func parseStatsCSV(resp string) (string, map[string]string) {
	body := resp
	// HAProxy responde con transfer-encoding: chunked; net/http lo decodifica.
	if r, err := http.ReadResponse(bufio.NewReader(strings.NewReader(resp)), nil); err == nil {
		if b, err := io.ReadAll(r.Body); err == nil {
			body = string(b)
		}
		r.Body.Close()
	}
	lines := strings.Split(strings.TrimSpace(body), "\n")
	if len(lines) == 0 {
		return "", nil
	}
	header := strings.Split(strings.TrimPrefix(lines[0], "# "), ",")
	col := map[string]int{}
	for i, h := range header {
		col[h] = i
	}
	get := func(f []string, k string) string {
		if i, ok := col[k]; ok && i < len(f) {
			return f[i]
		}
		return ""
	}
	states := map[string]string{}
	var b strings.Builder
	fmt.Fprintf(&b, "%-16s %-8s %-12s %-10s %s\n", "SERVIDOR", "ESTADO", "VERIFICACIÓN", "PETICIONES", "ÚLTIMO CAMBIO")
	var names []string
	rows := map[string][]string{}
	for _, l := range lines[1:] {
		f := strings.Split(l, ",")
		if get(f, "pxname") != "np2_servidores" {
			continue
		}
		sv := get(f, "svname")
		if sv == "BACKEND" || sv == "FRONTEND" {
			continue
		}
		names = append(names, sv)
		rows[sv] = f
		states[sv] = get(f, "status")
	}
	sort.Strings(names)
	for _, sv := range names {
		f := rows[sv]
		fmt.Fprintf(&b, "%-16s %-8s %-12s %-10s %ss\n", sv, get(f, "status"), get(f, "check_status"), get(f, "stot"), get(f, "lastchg"))
	}
	if len(names) == 0 {
		b.WriteString("(el backend no tiene servidores)\n")
	}
	return strings.TrimRight(b.String(), "\n"), states
}

// LBState muestra la configuración del balanceador y el estado de cada
// servidor, sin cambiar nada.
func LBState(ctx context.Context, rn runner.Runner) *Result {
	o := newRun(ctx, rn, "haproxy")
	cfg, _, ok := o.lbRead()
	if !ok {
		return o.res
	}
	if _, found, _ := parseLB(cfg); !found {
		return o.done()
	}
	if _, ok := o.lbStatus("Consultar el estado de los servidores"); !ok {
		return o.res
	}
	return o.done()
}

// AddServer implementa la primera parte del punto 3.4: agrega un servidor al
// backend del balanceador (y crea el balanceador si no existe).
func AddServer(ctx context.Context, rn runner.Runner, in LBAddInput) *Result {
	o := newRun(ctx, rn, "haproxy")
	if err := in.Validate(); err != nil {
		o.res.Steps = append(o.res.Steps, Step{Name: "Validar los datos", Detail: err.Error()})
		return o.res
	}
	cfg, hash, ok := o.lbRead()
	if !ok {
		return o.res
	}

	var next string
	if !o.step("Preparar la configuración nueva", func() (string, string, error) {
		c, found, err := parseLB(cfg)
		if err != nil {
			return "", "", err
		}
		for _, s := range c.Servers {
			if s.Name == in.Name {
				return "", "", fmt.Errorf("ya hay un servidor llamado %q en el backend (%s:%d): elimínelo primero o use otro nombre", s.Name, s.Addr, s.Port)
			}
			if s.Addr == in.Addr && s.Port == in.Port {
				return "", "", fmt.Errorf("%s:%d ya está en el backend como %q", s.Addr, s.Port, s.Name)
			}
		}
		if in.FrontPort != 0 {
			c.FrontPort = in.FrontPort
		}
		if in.Balance != "" {
			c.Balance = in.Balance
		}
		if portInUse(cfg, c.FrontPort) {
			return "", "", fmt.Errorf("otra sección de haproxy.cfg ya usa el puerto %d: elija otro puerto para el balanceador", c.FrontPort)
		}
		c.Servers = append(c.Servers, LBServer{Name: in.Name, Addr: in.Addr, Port: in.Port})
		if next, err = withLB(cfg, c); err != nil {
			return "", "", err
		}
		d := fmt.Sprintf("Se agrega %s (%s:%d) al backend np2_servidores", in.Name, in.Addr, in.Port)
		if !found {
			d += fmt.Sprintf("; se crea el frontend en el puerto %d (%s)", c.FrontPort, c.Balance)
		}
		return d, c.Render(), nil
	}) {
		return o.res
	}

	// Informativo: si el servidor todavía no responde, HAProxy lo marcará
	// DOWN y no le enviará tráfico hasta que responda.
	o.step("Comprobar que el servidor responda desde el balanceador", func() (string, string, error) {
		r, _ := o.remote("alcance", `
if timeout 3 bash -c 'exec 3<>"/dev/tcp/$1/$2"' _ `+runner.Quote(in.Addr)+` `+strconv.Itoa(in.Port)+` 2>/dev/null; then
  echo "responde"
else
  echo "no responde"
fi
`, time.Minute)
		if strings.Contains(r.Stdout, "no responde") || r.Stdout == "" {
			return fmt.Sprintf("%s:%d no responde todavía: se agrega igual, pero HAProxy lo marcará DOWN y no le enviará tráfico hasta que responda", in.Addr, in.Port), joinTech(r), nil
		}
		return fmt.Sprintf("%s:%d acepta conexiones", in.Addr, in.Port), joinTech(r), nil
	})

	if !o.lbApply(next, hash) {
		return o.res
	}
	states, ok := o.lbStatus("Verificar que el servidor esté en el backend")
	if !ok {
		return o.res
	}
	if _, present := states[in.Name]; !present {
		o.res.Steps[len(o.res.Steps)-1].OK = false
		o.res.Steps[len(o.res.Steps)-1].Detail = in.Name + " no aparece en las estadísticas de HAProxy"
		return o.res
	}
	return o.done()
}

// RemoveServer implementa la segunda parte del punto 3.4.
func RemoveServer(ctx context.Context, rn runner.Runner, name string) *Result {
	o := newRun(ctx, rn, "haproxy")
	if err := validate.ServerName(name); err != nil {
		o.res.Steps = append(o.res.Steps, Step{Name: "Validar los datos", Detail: err.Error()})
		return o.res
	}
	cfg, hash, ok := o.lbRead()
	if !ok {
		return o.res
	}
	var next string
	if !o.step("Preparar la configuración nueva", func() (string, string, error) {
		c, found, err := parseLB(cfg)
		if err != nil {
			return "", "", err
		}
		if !found {
			return "", "", errors.New("no hay balanceador configurado por esta aplicación en esta VM")
		}
		kept := c.Servers[:0:0]
		var removed *LBServer
		for _, s := range c.Servers {
			if s.Name == name {
				s := s
				removed = &s
				continue
			}
			kept = append(kept, s)
		}
		if removed == nil {
			return "", "", fmt.Errorf("no hay un servidor llamado %q en el backend%s", name, serverList(c.Servers))
		}
		c.Servers = kept
		if next, err = withLB(cfg, c); err != nil {
			return "", "", err
		}
		d := fmt.Sprintf("Se quita %s (%s:%d); quedan %d servidores", removed.Name, removed.Addr, removed.Port, len(kept))
		if len(kept) == 0 {
			d += ". Sin servidores, el balanceador responderá 503 hasta que agregue uno"
		}
		return d, c.Render(), nil
	}) {
		return o.res
	}
	if !o.lbApply(next, hash) {
		return o.res
	}
	states, ok := o.lbStatus("Verificar que el servidor ya no esté en el backend")
	if !ok {
		return o.res
	}
	if _, present := states[name]; present {
		o.res.Steps[len(o.res.Steps)-1].OK = false
		o.res.Steps[len(o.res.Steps)-1].Detail = name + " sigue apareciendo en las estadísticas de HAProxy"
		return o.res
	}
	return o.done()
}

// TestBalancer hace varias peticiones HTTP al balanceador desde la propia VM
// y cuenta qué servidor respondió cada una (cabecera X-Servidor).
func TestBalancer(ctx context.Context, rn runner.Runner, requests int) *Result {
	o := newRun(ctx, rn, "haproxy")
	cfg, _, ok := o.lbRead()
	if !ok {
		return o.res
	}
	c, found, err := parseLB(cfg)
	if err != nil || !found {
		o.res.Steps = append(o.res.Steps, Step{Name: "Probar el balanceo", Detail: "No hay balanceador configurado por esta aplicación: agregue primero un servidor."})
		return o.res
	}
	if !o.step(fmt.Sprintf("Enviar %d peticiones HTTP al balanceador (puerto %d)", requests, c.FrontPort), func() (string, string, error) {
		r, err := o.remote("probar", `
n=`+strconv.Itoa(requests)+`
port=`+strconv.Itoa(c.FrontPort)+`
for i in $(seq 1 "$n"); do
  resp=$(timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/'"$port"' && printf "GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n" >&3 && cat <&3' 2>/dev/null | tr -d '\r' | sed '/^$/q' || true)
  code=$(printf '%s\n' "$resp" | head -1 | awk '{print $2}')
  srv=$(printf '%s\n' "$resp" | sed -n 's/^[Xx]-[Ss]ervidor: *//p' | head -1)
  printf '%s\t%s\t%s\n' "$i" "${code:-sin-respuesta}" "${srv:--}"
done
`, 3*time.Minute)
		if err != nil {
			return "", joinTech(r), err
		}
		count := map[string]int{}
		var b strings.Builder
		fmt.Fprintf(&b, "%-9s %-8s %s\n", "PETICIÓN", "CÓDIGO", "ATENDIDA POR")
		for _, l := range strings.Split(strings.TrimSpace(r.Stdout), "\n") {
			f := strings.Split(l, "\t")
			if len(f) != 3 {
				continue
			}
			fmt.Fprintf(&b, "%-9s %-8s %s\n", f[0], f[1], f[2])
			if f[2] != "-" {
				count[f[2]]++
			}
		}
		o.res.Preview = strings.TrimRight(b.String(), "\n")
		if len(count) == 0 {
			return "", joinTech(r), errors.New("ninguna petición fue atendida por un servidor del backend: revise que los servidores estén UP")
		}
		var parts []string
		for _, s := range sortedKeys(count) {
			parts = append(parts, fmt.Sprintf("%s: %d", s, count[s]))
		}
		return "Peticiones atendidas por servidor: " + strings.Join(parts, " · "), "", nil
	}) {
		return o.res
	}
	return o.done()
}

func sortedKeys(m map[string]int) []string {
	k := make([]string, 0, len(m))
	for s := range m {
		k = append(k, s)
	}
	sort.Strings(k)
	return k
}

// LBAlgorithms devuelve los algoritmos disponibles (valor y descripción).
func LBAlgorithms() [][2]string {
	return [][2]string{
		{"roundrobin", lbAlgorithms["roundrobin"]},
		{"leastconn", lbAlgorithms["leastconn"]},
		{"source", lbAlgorithms["source"]},
	}
}
