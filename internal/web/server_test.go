package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"np2auto/internal/config"
)

func newTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	def := config.Default()
	def.DataDir = filepath.Join(dir, "data")
	raw, _ := json.Marshal(def)
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	store, _, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	// El destino "test" usa SSH con una llave inexistente: sirve para probar
	// los mensajes de error sin tocar ninguna VM.
	if err := store.Update("test", func(x *config.Target) { x.Transport = config.TransportSSH; x.KeyPath = filepath.Join(dir, "no-existe") }); err != nil {
		t.Fatal(err)
	}
	srv, err := New(store)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return srv, ts
}

// get hace una petición con el Host que el guardia acepta (localhost:8088).
func get(t *testing.T, ts *httptest.Server, path string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", ts.URL+path, nil)
	req.Host = "localhost:8088"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return resp, sb.String()
}

func post(t *testing.T, ts *httptest.Server, path string, form url.Values) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", ts.URL+path, strings.NewReader(form.Encode()))
	req.Host = "localhost:8088"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return resp, sb.String()
}

func TestPagesRender(t *testing.T) {
	_, ts := newTestServer(t)
	for path, want := range map[string]string{
		"/connection":            "Conexión con las VMs",
		"/prep/rootkey":          "Configurar llave de root",
		"/prep/hostname":         "Aplicar nombre de host",
		"/journal":               "Registro de operaciones",
		"/m/haproxy":             "Agregar un servidor al backend",
		"/m/users-create":        "casilla de sudo",
		"/connection?t=balancer": "VM del balanceador",
	} {
		resp, body := get(t, ts, path)
		if resp.StatusCode != 200 || !strings.Contains(body, want) {
			t.Errorf("%s: status %d, no contiene %q", path, resp.StatusCode, want)
		}
	}
	if resp, _ := get(t, ts, "/m/no-existe"); resp.StatusCode != 404 {
		t.Errorf("módulo inexistente: %d", resp.StatusCode)
	}
}

func TestCSRFAndHostGuard(t *testing.T) {
	srv, ts := newTestServer(t)

	// POST sin token CSRF.
	if resp, _ := post(t, ts, "/connection/test", url.Values{"t": {"test"}}); resp.StatusCode != 403 {
		t.Errorf("sin CSRF: %d, quería 403", resp.StatusCode)
	}
	// POST con token incorrecto.
	if resp, _ := post(t, ts, "/connection/test", url.Values{"t": {"test"}, "csrf": {"x"}}); resp.StatusCode != 403 {
		t.Errorf("CSRF incorrecto: %d, quería 403", resp.StatusCode)
	}
	// Host ajeno (DNS rebinding).
	req, _ := http.NewRequest("GET", ts.URL+"/connection", nil)
	req.Host = "evil.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Errorf("Host ajeno: %d, quería 403", resp.StatusCode)
	}
	// Con el token correcto la petición pasa.
	resp2, body := post(t, ts, "/connection/test", url.Values{"t": {"test"}, "csrf": {srv.csrf}})
	if resp2.StatusCode != 200 || !strings.Contains(body, "no se encuentra la llave privada") {
		t.Errorf("con CSRF válido: %d\n%s", resp2.StatusCode, body)
	}
}

func TestRootKeyRequiresConfirmation(t *testing.T) {
	srv, ts := newTestServer(t)
	resp, body := post(t, ts, "/prep/rootkey", url.Values{"t": {"test"}, "csrf": {srv.csrf}})
	if resp.StatusCode != 200 || !strings.Contains(body, "Marque la casilla de confirmación") {
		t.Errorf("sin confirmación debe rechazar: %d", resp.StatusCode)
	}
}

func TestTransportSwitch(t *testing.T) {
	srv, ts := newTestServer(t)
	_, body := post(t, ts, "/connection/transport", url.Values{"t": {"test"}, "csrf": {srv.csrf}, "transport": {"guest"}})
	if !strings.Contains(body, "Canal de comunicación actualizado") {
		t.Errorf("no actualizó: %s", body)
	}
	if cur, _ := srv.cfg.Target("test"); cur.Transport != "guest" {
		t.Errorf("transporte = %q", cur.Transport)
	}
	_, body = post(t, ts, "/connection/transport", url.Values{"t": {"test"}, "csrf": {srv.csrf}, "transport": {"telnet"}})
	if !strings.Contains(body, "transport debe ser") {
		t.Errorf("debía rechazar el valor inválido: %s", body)
	}
}

func TestDownload(t *testing.T) {
	srv, ts := newTestServer(t)
	if resp, _ := get(t, ts, "/download/inexistente"); resp.StatusCode != 404 {
		t.Errorf("token inexistente: %d", resp.StatusCode)
	}
	key := filepath.Join(t.TempDir(), "k")
	os.WriteFile(key, []byte("CLAVE-PRIVADA"), 0o600)
	tok := srv.dl.Add(key, "id_ed25519_root_test", time.Minute)
	resp, body := get(t, ts, "/download/"+tok)
	if resp.StatusCode != 200 || body != "CLAVE-PRIVADA" {
		t.Errorf("descarga: %d %q", resp.StatusCode, body)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "id_ed25519_root_test") {
		t.Errorf("Content-Disposition = %q", cd)
	}
	// Vencido.
	old := srv.dl.Add(key, "x", -time.Second)
	if resp, _ := get(t, ts, "/download/"+old); resp.StatusCode != 404 {
		t.Errorf("token vencido: %d", resp.StatusCode)
	}
}

func TestLockSet(t *testing.T) {
	l := newLockSet()
	unlock, ok := l.try("a")
	if !ok {
		t.Fatal("primer bloqueo debe funcionar")
	}
	if _, ok := l.try("a"); ok {
		t.Error("segundo bloqueo del mismo destino debe fallar")
	}
	if u2, ok := l.try("b"); !ok {
		t.Error("otro destino no debe estar bloqueado")
	} else {
		u2()
	}
	unlock()
	if _, ok := l.try("a"); !ok {
		t.Error("tras liberar debe poder bloquearse")
	}
}

func TestHostnameForm(t *testing.T) {
	srv, ts := newTestServer(t)
	// Datos inválidos: se rechazan antes de tocar la VM y se conservan en el formulario.
	_, body := post(t, ts, "/prep/hostname", url.Values{"t": {"test"}, "csrf": {srv.csrf}, "action": {"apply"}, "name": {"web1;reboot"}})
	if !strings.Contains(body, "nombre de host inválido") || !strings.Contains(body, `value="web1;reboot"`) {
		t.Errorf("debía rechazar el nombre inválido:\n%s", body)
	}
	_, body = post(t, ts, "/prep/hostname", url.Values{"t": {"test"}, "csrf": {srv.csrf}, "action": {"apply"}, "name": {"web1"}, "domain": {"lab..local"}})
	if !strings.Contains(body, "dominio inválido") {
		t.Errorf("debía rechazar el dominio inválido:\n%s", body)
	}
	// Datos válidos: llega hasta el canal, que aquí falla porque la llave no existe.
	_, body = post(t, ts, "/prep/hostname", url.Values{"t": {"test"}, "csrf": {srv.csrf}, "action": {"apply"}, "name": {"Web1"}})
	if !strings.Contains(body, "no se encuentra la llave privada") {
		t.Errorf("debía intentar conectar:\n%s", body)
	}
	_, body = post(t, ts, "/prep/hostname", url.Values{"t": {"test"}, "csrf": {srv.csrf}, "action": {"state"}})
	if !strings.Contains(body, "no se encuentra la llave privada") {
		t.Errorf("consultar estado debía intentar conectar:\n%s", body)
	}
}
