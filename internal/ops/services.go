package ops

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"np2auto/internal/runner"
	"np2auto/internal/validate"
)

// Tipos de servicio que ofrece la interfaz.
const (
	SvcSimple  = "simple"  // proceso que queda en ejecución (aplicación web)
	SvcOneshot = "oneshot" // script que se ejecuta y termina
)

// managedMarker identifica las unidades creadas por la aplicación: solo esas
// se pueden actualizar o desinstalar desde aquí.
const managedMarker = "# Gestionado por NP2 (consola de automatización)."

// ServiceInput son los datos del formulario de despliegue (punto 3.3).
type ServiceInput struct {
	Name     string   // nombre del servicio: unidad <Name>.service
	Source   string   // archivo o carpeta en el equipo donde corre la consola
	Exec     string   // ejecutable relativo a la carpeta (vacío si Source es un archivo)
	Args     []string // argumentos (validados)
	Env      []string // NOMBRE=valor (validados)
	Type     string   // SvcSimple o SvcOneshot
	LowPorts bool     // permitir puertos menores que 1024 sin ser root
	Start    bool     // habilitar al arranque e iniciar ahora
}

func (in ServiceInput) unit() string { return in.Name + ".service" }
func (in ServiceInput) dir() string  { return "/opt/" + in.Name }
func (in ServiceInput) user() string { return "svc-" + in.Name }

// Validate comprueba los datos (sin tocar la VM ni los archivos).
func (in ServiceInput) Validate() error {
	if err := validate.ServiceName(in.Name); err != nil {
		return err
	}
	if !filepath.IsAbs(in.Source) {
		return errors.New("indique la ruta completa (absoluta) del archivo o la carpeta en este equipo, p. ej. /Users/ana/catalogo")
	}
	if in.Exec != "" {
		if err := validate.RelPath(in.Exec); err != nil {
			return err
		}
	}
	if in.Type != SvcSimple && in.Type != SvcOneshot {
		return fmt.Errorf("tipo de servicio inválido %q", in.Type)
	}
	for _, a := range in.Args {
		if _, err := validate.ExecArgs(a); err != nil {
			return err
		}
	}
	for _, e := range in.Env {
		if _, err := validate.EnvVars(e); err != nil {
			return err
		}
	}
	return nil
}

// UnitFile arma el contenido de /etc/systemd/system/<nombre>.service.
func (in ServiceInput) UnitFile() string {
	var b strings.Builder
	w := func(s string) { b.WriteString(s + "\n") }
	w(managedMarker)
	w("[Unit]")
	w("Description=" + in.Name + " (desplegado por NP2)")
	w("After=network-online.target")
	w("Wants=network-online.target")
	w("")
	w("[Service]")
	w("Type=" + in.Type)
	w("User=" + in.user())
	w("Group=" + in.user())
	w("WorkingDirectory=" + in.dir())
	exec := in.dir() + "/" + in.Exec
	if len(in.Args) > 0 {
		exec += " " + strings.Join(in.Args, " ")
	}
	w("ExecStart=" + exec)
	for _, e := range in.Env {
		w("Environment=" + e)
	}
	if in.Type == SvcSimple {
		w("Restart=on-failure")
		w("RestartSec=3")
	}
	if in.LowPorts {
		w("AmbientCapabilities=CAP_NET_BIND_SERVICE")
	}
	w("NoNewPrivileges=yes")
	w("")
	w("[Install]")
	w("WantedBy=multi-user.target")
	return b.String()
}

// checkExecutable revisa en este equipo que el ejecutable pueda correr en la
// VM: un binario ELF (Linux) o un script con "#!". Un binario de macOS o de
// Windows fallaría en la VM con "Exec format error".
func checkExecutable(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	head := make([]byte, 4)
	n, _ := f.Read(head)
	head = head[:n]
	switch {
	case bytes.HasPrefix(head, []byte("\x7fELF")):
		return "binario ELF (Linux)", nil
	case bytes.HasPrefix(head, []byte("#!")):
		return "script con intérprete (#!)", nil
	case bytes.Equal(head, []byte{0xcf, 0xfa, 0xed, 0xfe}), bytes.Equal(head, []byte{0xce, 0xfa, 0xed, 0xfe}), bytes.Equal(head, []byte{0xca, 0xfe, 0xba, 0xbe}):
		return "", errors.New("el ejecutable es un binario de macOS y no corre en Debian: compílelo para Linux (en Go: GOOS=linux GOARCH=amd64 go build)")
	case bytes.HasPrefix(head, []byte("MZ")):
		return "", errors.New("el ejecutable es un binario de Windows y no corre en Debian: compílelo para Linux")
	default:
		return "", errors.New("el ejecutable no es un binario de Linux ni un script que empiece con #! (por ejemplo #!/bin/bash)")
	}
}

// DeployService implementa la primera parte del punto 3.3: transfiere la
// aplicación a /opt/<nombre>, le da un usuario propio, ajusta permisos y la
// registra como servicio de systemd.
func DeployService(ctx context.Context, rn runner.Runner, in ServiceInput) *Result {
	o := newRun(ctx, rn, "servicios")
	fail := func(name, msg string) *Result {
		o.res.Steps = append(o.res.Steps, Step{Name: name, Detail: msg})
		return o.res
	}
	if err := in.Validate(); err != nil {
		return fail("Validar los datos", err.Error())
	}

	// 1. Archivos de origen (en este equipo).
	var b *bundle
	if !o.step("Revisar los archivos en este equipo", func() (string, string, error) {
		var err error
		if b, err = scanBundle(in.Source); err != nil {
			return "", "", err
		}
		info, _ := os.Stat(in.Source)
		if !info.IsDir() {
			in.Exec = filepath.Base(in.Source)
			if validate.RelPath(in.Exec) != nil {
				return "", "", fmt.Errorf("el nombre del archivo %q tiene caracteres no permitidos (use letras, dígitos, _ . -)", in.Exec)
			}
		} else if in.Exec == "" {
			return "", "", errors.New("indique cuál es el ejecutable dentro de la carpeta")
		}
		if !b.has(in.Exec) {
			return "", "", fmt.Errorf("no se encontró el ejecutable %q dentro de %s", in.Exec, in.Source)
		}
		kind, err := checkExecutable(filepath.Join(b.root, filepath.FromSlash(in.Exec)))
		if err != nil {
			return "", "", err
		}
		return b.summary() + ". Ejecutable: " + in.Exec + " (" + kind + ")", "", nil
	}) {
		return o.res
	}

	unit, dir, user := runner.Quote(in.unit()), runner.Quote(in.dir()), runner.Quote(in.user())
	vars := "unit=" + unit + "\ndir=" + dir + "\nuser=" + user + "\nf=/etc/systemd/system/$unit\n"

	// 2. Que la unidad sea nueva o creada por esta aplicación.
	if !o.step("Comprobar systemd y el nombre del servicio", func() (string, string, error) {
		r, err := o.remote("comprobar", vars+`
command -v systemctl >/dev/null || { echo "systemctl no está disponible en la VM" >&2; exit 1; }
if [ -f "$f" ]; then
  if grep -qxF `+runner.Quote(managedMarker)+` "$f"; then echo "$unit ya existe (creado por esta aplicación): se actualizará"
  else echo "$unit ya existe y no lo creó esta aplicación: elija otro nombre" >&2; exit 1; fi
elif systemctl cat "$unit" >/dev/null 2>&1; then
  echo "$unit ya existe en el sistema: elija otro nombre" >&2; exit 1
else
  echo "$unit es un servicio nuevo"
fi
`, time.Minute)
		return firstLines(r.Stdout, 1), joinTech(r), err
	}) {
		return o.res
	}

	// 3. Usuario de sistema propio: el servicio no corre como root.
	if !o.step("Crear el usuario de sistema "+in.user(), func() (string, string, error) {
		r, err := o.remote("usuario", vars+`
if id -u "$user" >/dev/null 2>&1; then
  echo "$user ya existe"
else
  useradd --system --user-group --no-create-home --home-dir "$dir" --shell /usr/sbin/nologin -- "$user"
  echo "creado $user (sin contraseña ni shell de inicio de sesión)"
fi
`, time.Minute)
		return firstLines(r.Stdout, 1), joinTech(r), err
	}) {
		return o.res
	}

	// 4. Transferencia por SSH (tar.gz por la entrada estándar).
	up, ok := rn.(runner.Uploader)
	if !ok {
		return fail("Transferir los archivos a la VM", "La transferencia de archivos requiere el canal SSH: configure primero la llave SSH de root.")
	}
	if !o.step("Transferir los archivos a la VM por SSH", func() (string, string, error) {
		stream := b.stream()
		defer stream.Close()
		c, cancel := context.WithTimeout(runner.WithOp(o.ctx, "servicios/transferir"), 30*time.Minute)
		defer cancel()
		r, err := up.RunInput(c, vars+`
st="/opt/.np2-$unit.new"
rm -rf "$st"
install -d -m 750 "$st"
tar -xzf - --no-same-owner -C "$st"
echo "recibidos en la VM: $(find "$st" -type f | wc -l) archivos, $(du -sh "$st" | cut -f1)"
`, stream)
		return firstLines(r.Stdout, 1), joinTech(r), err
	}) {
		return o.res
	}

	// 5. Instalar en /opt/<nombre> y ajustar permisos.
	if !o.step("Instalar en "+in.dir()+" y ajustar permisos", func() (string, string, error) {
		r, err := o.remote("instalar", vars+`
st="/opt/.np2-$unit.new"
exe=`+runner.Quote(in.Exec)+`
[ -f "$st/$exe" ] || { echo "no llegó el ejecutable $exe" >&2; exit 1; }
if systemctl is-active --quiet "$unit"; then systemctl stop "$unit"; echo "se detuvo la versión anterior"; fi
rm -rf "$dir.old"
if [ -d "$dir" ]; then mv "$dir" "$dir.old"; fi
mv "$st" "$dir"
rm -rf "$dir.old"
chown -R "$user:$user" "$dir"
chmod -R u+rwX,g+rX,g-w,o-rwx "$dir"
chmod 750 "$dir/$exe"
echo "instalado en $dir (dueño $user, sin acceso para otros usuarios)"
ls -l "$dir"
`, 2*time.Minute)
		return firstLines(r.Stdout, 2), joinTech(r), err
	}) {
		return o.res
	}

	// 6. Unidad de systemd.
	if !o.step("Crear la unidad /etc/systemd/system/"+in.unit(), func() (string, string, error) {
		r, err := o.remote("unidad", vars+`
printf '%s' `+runner.Quote(in.UnitFile())+` > "$f"
chmod 644 "$f"
systemctl daemon-reload
if command -v systemd-analyze >/dev/null; then
  systemd-analyze verify "$f" 2>&1 | grep -v -e '^$' || true
fi
echo "unidad creada y systemd recargado"
cat "$f"
`, time.Minute)
		return "Unidad creada y systemd recargado (daemon-reload)", joinTech(r), err
	}) {
		return o.res
	}

	// 7. Habilitar e iniciar.
	if in.Start {
		if !o.step("Habilitar al arranque e iniciar el servicio", func() (string, string, error) {
			r, err := o.remote("iniciar", vars+`
systemctl enable "$unit" 2>&1
systemctl restart "$unit"
echo "habilitado e iniciado"
`, 3*time.Minute)
			return "systemctl enable + restart " + in.unit(), joinTech(r), err
		}) {
			o.statusPreview(in.unit())
			return o.res
		}
	}

	// 8. Estado final.
	if !o.unitCheck(in.unit(), func(st unitState) error {
		if !in.Start {
			return nil
		}
		return st.expectRunning()
	}) {
		return o.res
	}
	return o.done()
}

// unitState son los datos de una unidad que se comprueban tras cada acción.
type unitState struct {
	Active, Enabled, Type, Result string
}

func (s unitState) String() string {
	return fmt.Sprintf("activo: %s · habilitado: %s · tipo: %s", s.Active, s.Enabled, s.Type)
}

// expectRunning: un servicio simple debe quedar "active"; uno oneshot ya
// terminó, así que se mira que su última ejecución haya sido exitosa.
func (s unitState) expectRunning() error {
	if s.Type == SvcOneshot {
		if s.Result != "success" {
			return fmt.Errorf("la última ejecución terminó con resultado %q", s.Result)
		}
		return nil
	}
	if s.Active != "active" {
		return fmt.Errorf("el servicio quedó %q en lugar de \"active\": revise el estado y el registro (journalctl) abajo", s.Active)
	}
	return nil
}

func unitStateScript(unit string) string {
	return `
u=` + runner.Quote(unit) + `
systemctl cat "$u" >/dev/null 2>&1 || { echo "la unidad $u no existe en la VM" >&2; exit 1; }
echo "activo=$(systemctl is-active "$u" 2>/dev/null || true)"
echo "habilitado=$(systemctl is-enabled "$u" 2>/dev/null || true)"
echo "tipo=$(systemctl show -p Type --value "$u")"
echo "resultado=$(systemctl show -p Result --value "$u")"
echo "---"
SYSTEMD_COLORS=0 systemctl status --no-pager -l --lines=15 "$u" 2>&1 || true
`
}

func parseUnitState(out string) (unitState, string) {
	head, status, _ := strings.Cut(out, "---\n")
	var s unitState
	for _, l := range strings.Split(head, "\n") {
		k, v, _ := strings.Cut(l, "=")
		switch k {
		case "activo":
			s.Active = v
		case "habilitado":
			s.Enabled = v
		case "tipo":
			s.Type = v
		case "resultado":
			s.Result = v
		}
	}
	return s, strings.TrimRight(status, "\n")
}

// unitCheck consulta el estado de la unidad, lo deja en la vista previa y
// aplica la comprobación indicada.
func (o *opRun) unitCheck(unit string, check func(unitState) error) bool {
	return o.step("Consultar el estado de "+unit, func() (string, string, error) {
		r, err := o.remote("estado", unitStateScript(unit), time.Minute)
		if err != nil {
			return "", joinTech(r), err
		}
		st, status := parseUnitState(r.Stdout)
		o.res.Preview = status
		if err := check(st); err != nil {
			return "", "", errors.New(st.String() + ". " + err.Error())
		}
		return st.String(), "", nil
	})
}

// statusPreview deja el estado en la vista previa sin agregar un paso (se
// usa cuando una acción falla, para ver el porqué).
func (o *opRun) statusPreview(unit string) {
	if r, err := o.remote("estado", unitStateScript(unit), time.Minute); err == nil {
		_, o.res.Preview = parseUnitState(r.Stdout)
	}
}

// Acciones de la segunda parte del punto 3.3.
var unitActions = map[string]string{
	"start": "Iniciar", "stop": "Detener", "restart": "Reiniciar",
	"status": "Consultar el estado", "enable": "Habilitar al arranque", "disable": "Deshabilitar del arranque",
}

// criticalUnits no se pueden detener ni deshabilitar desde la consola:
// cortarían el acceso a la VM o la dejarían inestable.
var criticalUnits = map[string]bool{
	"ssh.service": true, "sshd.service": true, "networking.service": true,
	"systemd-networkd.service": true, "NetworkManager.service": true, "dbus.service": true,
	"systemd-journald.service": true, "systemd-logind.service": true, "systemd-resolved.service": true,
}

// UnitAction ejecuta start, stop, restart, status, enable o disable sobre una
// unidad y comprueba que el estado resultante sea el esperado.
func UnitAction(ctx context.Context, rn runner.Runner, unit, action string) *Result {
	o := newRun(ctx, rn, "servicios")
	label, ok := unitActions[action]
	if !ok {
		o.res.Steps = append(o.res.Steps, Step{Name: "Validar los datos", Detail: "acción desconocida " + action})
		return o.res
	}
	u, err := validate.UnitName(unit)
	if err != nil {
		o.res.Steps = append(o.res.Steps, Step{Name: "Validar los datos", Detail: err.Error()})
		return o.res
	}
	if (action == "stop" || action == "disable") && criticalUnits[u] {
		o.res.Steps = append(o.res.Steps, Step{Name: label + " " + u, Detail: u + " es necesario para administrar la VM (acceso SSH, red o sistema): no se puede detener ni deshabilitar desde aquí."})
		return o.res
	}
	if action != "status" {
		if !o.step(label+" "+u+" (systemctl "+action+")", func() (string, string, error) {
			r, err := o.remote(action, `
u=`+runner.Quote(u)+`
systemctl cat "$u" >/dev/null 2>&1 || { echo "la unidad $u no existe en la VM" >&2; exit 1; }
systemctl `+action+` "$u" 2>&1
echo "systemctl `+action+` $u: correcto"
`, 3*time.Minute)
			return lastLine(r.Stdout), joinTech(r), err
		}) {
			o.statusPreview(u)
			return o.res
		}
	}
	if !o.unitCheck(u, func(st unitState) error {
		switch action {
		case "start", "restart":
			return st.expectRunning()
		case "stop":
			if st.Active == "active" {
				return errors.New("el servicio sigue activo")
			}
		case "enable":
			if st.Enabled != "enabled" {
				return fmt.Errorf("quedó %q en lugar de \"enabled\"", st.Enabled)
			}
		case "disable":
			if st.Enabled == "enabled" {
				return errors.New("sigue habilitado")
			}
		}
		return nil
	}) {
		return o.res
	}
	return o.done()
}

// ListServices muestra las unidades creadas por la aplicación.
func ListServices(ctx context.Context, rn runner.Runner) *Result {
	o := newRun(ctx, rn, "servicios")
	if !o.step("Listar los servicios desplegados por la aplicación", func() (string, string, error) {
		r, err := o.remote("listar", `
printf '%-24s %-10s %-10s %s\n' UNIDAD ACTIVO HABILITADO DIRECTORIO
n=0
for f in /etc/systemd/system/*.service; do
  [ -f "$f" ] && grep -qxF `+runner.Quote(managedMarker)+` "$f" || continue
  u=$(basename "$f")
  printf '%-24s %-10s %-10s %s\n' "$u" "$(systemctl is-active "$u" 2>/dev/null || true)" "$(systemctl is-enabled "$u" 2>/dev/null || true)" "$(sed -n 's/^WorkingDirectory=//p' "$f")"
  n=$((n+1))
done
[ "$n" -gt 0 ] || echo "(ninguno todavía)"
`, time.Minute)
		if err == nil {
			o.res.Preview = strings.TrimRight(r.Stdout, "\n")
		}
		return "Servicios con la marca de esta aplicación en /etc/systemd/system", "", err
	}) {
		return o.res
	}
	return o.done()
}

// UndeployService retira un servicio creado por la aplicación: lo detiene,
// borra la unidad, la carpeta /opt/<nombre> y el usuario svc-<nombre>.
func UndeployService(ctx context.Context, rn runner.Runner, name string) *Result {
	o := newRun(ctx, rn, "servicios")
	if err := validate.ServiceName(name); err != nil {
		o.res.Steps = append(o.res.Steps, Step{Name: "Validar los datos", Detail: err.Error()})
		return o.res
	}
	in := ServiceInput{Name: name}
	if !o.step("Desinstalar "+in.unit(), func() (string, string, error) {
		r, err := o.remote("desinstalar", `
unit=`+runner.Quote(in.unit())+`
dir=`+runner.Quote(in.dir())+`
user=`+runner.Quote(in.user())+`
f=/etc/systemd/system/$unit
[ -f "$f" ] && grep -qxF `+runner.Quote(managedMarker)+` "$f" || { echo "$unit no existe o no lo creó esta aplicación: no se toca" >&2; exit 1; }
systemctl disable --now "$unit" 2>&1 || true
rm -f "$f"
systemctl daemon-reload
systemctl reset-failed "$unit" 2>/dev/null || true
rm -rf "$dir"
if id -u "$user" >/dev/null 2>&1; then userdel "$user"; fi
echo "se eliminaron $unit, $dir y el usuario $user"
`, 3*time.Minute)
		return lastLine(r.Stdout), joinTech(r), err
	}) {
		return o.res
	}
	if !o.step("Verificar", func() (string, string, error) {
		r, err := o.remote("verificar", `
unit=`+runner.Quote(in.unit())+`
if systemctl cat "$unit" >/dev/null 2>&1; then echo "$unit sigue existiendo" >&2; exit 1; fi
[ ! -e `+runner.Quote(in.dir())+` ] || { echo "la carpeta sigue existiendo" >&2; exit 1; }
echo "$unit ya no existe"
`, time.Minute)
		return lastLine(r.Stdout), joinTech(r), err
	}) {
		return o.res
	}
	return o.done()
}
