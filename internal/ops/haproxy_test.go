package ops

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"np2auto/internal/runner"
)

// debianCfg es haproxy.cfg tal como lo deja el paquete (configuración
// predeterminada, la precondición del enunciado).
func debianCfg(t *testing.T) string {
	b, err := os.ReadFile("testdata/haproxy-debian.cfg")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestLBRoundTrip(t *testing.T) {
	base := debianCfg(t)
	if _, found, _ := parseLB(base); found {
		t.Fatal("la configuración predeterminada no tiene bloque")
	}
	c := LBConfig{FrontPort: 8080, Balance: "leastconn", Servers: []LBServer{{"web1", "192.168.1.70", 80}, {"web2", "fd00::2", 8080}}}
	cfg, err := withLB(base, c)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(cfg, base) {
		t.Error("el resto del archivo no debe cambiar")
	}
	got, found, err := parseLB(cfg)
	if err != nil || !found || fmt.Sprint(got) != fmt.Sprint(c) {
		t.Fatalf("parse: %+v %v %v", got, found, err)
	}
	// Reemplazar el bloque no lo duplica ni toca lo de después.
	c.Servers = c.Servers[:1]
	cfg2, _ := withLB(cfg+"\n# línea del usuario\n", c)
	if strings.Count(cfg2, lbBegin) != 1 || !strings.Contains(cfg2, "# línea del usuario") || strings.Contains(cfg2, "web2") {
		t.Errorf("reemplazo:\n%s", cfg2)
	}
	if _, _, err := parseLB(base + lbBegin + "\nfrontend x\n"); err == nil {
		t.Error("un bloque sin marca final debe dar error")
	}
}

func TestPortInUse(t *testing.T) {
	cfg := debianCfg(t) + "\nfrontend mio\n    bind *:80\n    default_backend b\n"
	if !portInUse(cfg, 80) || portInUse(cfg, 8080) {
		t.Error("detección de puertos ocupados")
	}
	// El propio bloque no cuenta.
	own, _ := withLB(debianCfg(t), defaultLB())
	if portInUse(own, 80) {
		t.Error("el bloque de la aplicación no debe contar como conflicto")
	}
}

// TestLBConfigValidWithHAProxy valida el resultado con el haproxy real.
func TestLBConfigValidWithHAProxy(t *testing.T) {
	if _, err := exec.LookPath("haproxy"); err != nil {
		t.Skip("haproxy no disponible")
	}
	cfg, _ := withLB(debianCfg(t), LBConfig{FrontPort: 80, Balance: "roundrobin", Servers: []LBServer{{"web1", "192.168.1.70", 8080}, {"web2", "192.168.1.71", 8080}}})
	p := filepath.Join(t.TempDir(), "haproxy.cfg")
	os.WriteFile(p, []byte(cfg), 0o644)
	out, err := exec.Command("haproxy", "-c", "-f", p).CombinedOutput()
	if err != nil {
		t.Fatalf("haproxy -c rechazó la configuración: %v\n%s\n%s", err, out, cfg)
	}
	// Sin servidores también es válida.
	cfg, _ = withLB(debianCfg(t), defaultLB())
	os.WriteFile(p, []byte(cfg), 0o644)
	if out, err := exec.Command("haproxy", "-c", "-f", p).CombinedOutput(); err != nil {
		t.Fatalf("sin servidores: %v\n%s", err, out)
	}
}

func lbFake(cfg string, extra map[string]string) *fakeRunner {
	out := map[string]string{"haproxy/leer": "HAProxy version 3.0.11\n" + cfg}
	for k, v := range extra {
		out[k] = v
	}
	return &fakeRunner{stdout: out}
}

const statsCSV = "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n" +
	"# pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,dreq,dresp,ereq,econ,eresp,wretr,wredis,status,weight,act,bck,chkfail,chkdown,lastchg,downtime,qlimit,pid,iid,sid,throttle,lbtot,tracked,type,rate,rate_lim,rate_max,check_status\n" +
	"np2_balanceador,FRONTEND,,,0,0,262124,0,0,0,0,0,0,,,,,OPEN,,,,,,,,,1,2,0,,,,0,0,0,0,\n" +
	"np2_servidores,web1,0,0,0,0,,4,0,0,,0,,0,0,0,0,UP,1,1,0,0,0,12,0,,1,3,1,,4,,2,0,,0,L4OK\n" +
	"np2_servidores,web2,0,0,0,0,,0,0,0,,0,,0,0,0,0,DOWN,1,1,0,1,1,3,3,,1,3,2,,0,,2,0,,0,L4CON\n" +
	"np2_servidores,BACKEND,0,0,0,0,26213,4,0,0,0,0,,0,0,0,0,UP,1,1,0,,0,12,0,,1,3,0,,4,,1,0,,0,\n"

func TestParseStatsCSV(t *testing.T) {
	table, st := parseStatsCSV(statsCSV)
	if st["web1"] != "UP" || st["web2"] != "DOWN" || len(st) != 2 {
		t.Errorf("estados: %v", st)
	}
	if !strings.Contains(table, "web2             DOWN     L4CON") {
		t.Errorf("tabla:\n%s", table)
	}
}

func TestAddServerFlow(t *testing.T) {
	f := lbFake(debianCfg(t), map[string]string{"haproxy/estado": statsCSV, "haproxy/alcance": "responde\n"})
	res := AddServer(context.Background(), f, LBAddInput{Name: "web2", Addr: "192.168.1.71", Port: 8080})
	if !res.OK {
		t.Fatalf("debería terminar bien: %+v", res.Steps)
	}
	want := "haproxy/leer,haproxy/alcance,haproxy/aplicar,haproxy/estado"
	if got := strings.Join(f.ops, ","); got != want {
		t.Errorf("pasos %s; quería %s", got, want)
	}
	apply := f.scripts[2]
	sum := sha256.Sum256([]byte(debianCfg(t)))
	if !strings.Contains(apply, hex.EncodeToString(sum[:])) {
		t.Error("debe comprobar que el archivo no cambió desde que se leyó")
	}
	for _, s := range []string{"server web2 192.168.1.71:8080 check", "bind *:80", "haproxy -c -f", "np2-prev"} {
		if !strings.Contains(apply, s) {
			t.Errorf("falta %q en el script de aplicación", s)
		}
	}
	if !strings.Contains(res.Steps[1].Detail, "se crea el frontend en el puerto 80") {
		t.Errorf("detalle: %q", res.Steps[1].Detail)
	}
	if !strings.Contains(res.Preview, "web2") {
		t.Errorf("vista previa: %q", res.Preview)
	}
}

func TestAddServerRejectsDuplicatesAndConflicts(t *testing.T) {
	cfg, _ := withLB(debianCfg(t), LBConfig{FrontPort: 80, Balance: "roundrobin", Servers: []LBServer{{"web1", "192.168.1.70", 8080}}})
	for _, c := range []struct {
		cfg  string
		in   LBAddInput
		want string
	}{
		{cfg, LBAddInput{Name: "web1", Addr: "192.168.1.99", Port: 80}, "ya hay un servidor llamado"},
		{cfg, LBAddInput{Name: "web9", Addr: "192.168.1.70", Port: 8080}, "ya está en el backend"},
		{debianCfg(t) + "\nfrontend mio\n    bind *:80\n", LBAddInput{Name: "web1", Addr: "192.168.1.70", Port: 8080}, "ya usa el puerto 80"},
	} {
		f := lbFake(c.cfg, nil)
		res := AddServer(context.Background(), f, c.in)
		if res.OK || !strings.Contains(res.Steps[len(res.Steps)-1].Detail, c.want) || len(f.ops) != 1 {
			t.Errorf("%+v: quería %q sin aplicar; %+v %v", c.in, c.want, res.Steps, f.ops)
		}
	}
	for _, in := range []LBAddInput{
		{Name: "web 1", Addr: "1.2.3.4", Port: 80},
		{Name: "web1", Addr: "1.2.3.4;id", Port: 80},
		{Name: "web1", Addr: "1.2.3.4", Port: 0},
		{Name: "web1", Addr: "1.2.3.4", Port: 80, FrontPort: lbStatPort},
		{Name: "web1", Addr: "1.2.3.4", Port: 80, Balance: "random;id"},
	} {
		f := &fakeRunner{}
		if res := AddServer(context.Background(), f, in); res.OK || len(f.ops) != 0 {
			t.Errorf("%+v: no debe tocar la VM", in)
		}
	}
}

func TestRemoveServerFlow(t *testing.T) {
	cfg, _ := withLB(debianCfg(t), LBConfig{FrontPort: 80, Balance: "roundrobin", Servers: []LBServer{{"web1", "192.168.1.70", 8080}, {"web2", "192.168.1.71", 8080}}})
	stats := strings.Replace(statsCSV, "np2_servidores,web2", "otro,web2", 1)
	f := lbFake(cfg, map[string]string{"haproxy/estado": stats})
	res := RemoveServer(context.Background(), f, "web2")
	if !res.OK {
		t.Fatalf("debería terminar bien: %+v", res.Steps)
	}
	if strings.Contains(f.scripts[1], "web2") || !strings.Contains(f.scripts[1], "server web1") {
		t.Errorf("script de aplicación: %s", f.scripts[1])
	}
	// Si sigue en las estadísticas, falla.
	f = lbFake(cfg, map[string]string{"haproxy/estado": statsCSV})
	if res := RemoveServer(context.Background(), f, "web2"); res.OK {
		t.Error("debe detectar que el servidor sigue en el backend")
	}
	f = lbFake(cfg, nil)
	if res := RemoveServer(context.Background(), f, "web9"); res.OK || !strings.Contains(res.Steps[1].Detail, "no hay un servidor llamado") {
		t.Errorf("servidor inexistente: %+v", res.Steps)
	}
	f = lbFake(debianCfg(t), nil)
	if res := RemoveServer(context.Background(), f, "web1"); res.OK || !strings.Contains(res.Steps[1].Detail, "no hay balanceador") {
		t.Errorf("sin balanceador: %+v", res.Steps)
	}
}

func TestLBReadRequiresHAProxy(t *testing.T) {
	f := &fakeRunner{failOn: "haproxy/leer"}
	if res := LBState(context.Background(), f); res.OK {
		t.Error("debe fallar si no se puede leer la configuración")
	}
}

// TestHAProxyEndToEnd levanta HAProxy de verdad con dos servidores web de
// prueba y ejecuta los scripts reales de estado y de prueba de balanceo.
func TestHAProxyEndToEnd(t *testing.T) {
	for _, bin := range []string{"haproxy", "bash", "timeout"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skip(bin + " no disponible")
		}
	}
	if ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", lbStatPort)); err != nil {
		t.Skip("puerto de estadísticas ocupado")
	} else {
		ln.Close()
	}
	var servers []LBServer
	for i := 1; i <= 2; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		name := fmt.Sprintf("web%d", i)
		go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "hola desde "+name) }))
		t.Cleanup(func() { ln.Close() })
		servers = append(servers, LBServer{Name: name, Addr: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port})
	}
	// Un tercero apagado: debe aparecer DOWN.
	servers = append(servers, LBServer{Name: "web3", Addr: "127.0.0.1", Port: 1})
	front, _ := net.Listen("tcp", "127.0.0.1:0")
	frontPort := front.Addr().(*net.TCPAddr).Port
	front.Close()

	global := "global\n    maxconn 100\n\ndefaults\n    mode http\n    timeout connect 2s\n    timeout client 5s\n    timeout server 5s\n    default-server inter 500ms\n\n"
	cfg, _ := withLB(global, LBConfig{FrontPort: frontPort, Balance: "roundrobin", Servers: servers})
	p := filepath.Join(t.TempDir(), "haproxy.cfg")
	os.WriteFile(p, []byte(cfg), 0o644)
	cmd := exec.Command("haproxy", "-db", "-f", p)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	time.Sleep(1500 * time.Millisecond)

	// Los scripts leen haproxy.cfg de /etc; aquí se simula esa lectura y lo
	// demás corre de verdad con bash contra el HAProxy levantado.
	lr := &cfgRunner{cfg: cfg}
	st := LBState(context.Background(), lr)
	t.Logf("\n%s", st.Preview)
	if !st.OK || !strings.Contains(st.Preview, "web1             UP") || !strings.Contains(st.Preview, "web3             DOWN") {
		t.Fatalf("estado: %+v\n%s", st.Steps, st.Preview)
	}
	tb := TestBalancer(context.Background(), lr, 6)
	t.Logf("\n%s", tb.Preview)
	if !tb.OK || !strings.Contains(tb.Steps[1].Detail, "web1: 3 · web2: 3") {
		t.Fatalf("balanceo: %+v\n%s", tb.Steps, tb.Preview)
	}
}

// cfgRunner responde la lectura de haproxy.cfg con un contenido dado y
// ejecuta todo lo demás con bash local.
type cfgRunner struct{ cfg string }

func (c *cfgRunner) Transport() string { return "local" }
func (c *cfgRunner) Describe() string  { return "local" }
func (c *cfgRunner) Run(ctx context.Context, script string) (runner.Result, error) {
	if strings.Contains(script, "cat /etc/haproxy/haproxy.cfg") {
		return runner.Result{Stdout: "HAProxy local\n" + c.cfg}, nil
	}
	return localRunner{}.Run(ctx, script)
}
