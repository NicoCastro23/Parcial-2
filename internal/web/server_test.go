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
		"/prep/packages":         "Instalar y eliminar aplicaciones",
		"/prep/issue":            "Aplicar en /etc/issue",
		"/journal":               "Registro de operaciones",
		"/m/haproxy":             "Agregar un servidor al backend",
		"/services":              "Desplegar servicio",
		"/users/create":          "Privilegios de sudo",
		"/users/delete":          "Eliminar también todos sus archivos",
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

func TestPackagesForm(t *testing.T) {
	srv, ts := newTestServer(t)
	base := url.Values{"t": {"test"}, "csrf": {srv.csrf}}
	with := func(kv ...string) url.Values {
		v := url.Values{}
		for k, x := range base {
			v[k] = x
		}
		for i := 0; i < len(kv); i += 2 {
			v.Set(kv[i], kv[i+1])
		}
		return v
	}
	_, body := post(t, ts, "/prep/packages", with("action", "install", "packages", "vim; reboot"))
	if !strings.Contains(body, "nombre de paquete inválido") {
		t.Errorf("debía rechazar la inyección:\n%s", body)
	}
	_, body = post(t, ts, "/prep/packages", with("action", "install", "packages", "  "))
	if !strings.Contains(body, "indique al menos un paquete") {
		t.Errorf("debía pedir un paquete:\n%s", body)
	}
	_, body = post(t, ts, "/prep/packages", with("action", "upgrade", "packages", "htop"))
	if !strings.Contains(body, "Acción desconocida") {
		t.Errorf("debía rechazar la acción:\n%s", body)
	}
	for _, action := range []string{"install", "remove", "state"} {
		_, body = post(t, ts, "/prep/packages", with("action", action, "packages", "HTOP, tree", "purge", "yes"))
		if !strings.Contains(body, "no se encuentra la llave privada") || !strings.Contains(body, `value="HTOP, tree"`) || !strings.Contains(body, "checked") {
			t.Errorf("%s: debía intentar conectar y conservar el formulario:\n%s", action, body)
		}
	}
}

func TestIssueForm(t *testing.T) {
	srv, ts := newTestServer(t)
	// Por defecto vienen marcadas las casillas que pide el enunciado.
	_, body := get(t, ts, "/prep/issue?t=test")
	if strings.Count(body, "checked") != 5 {
		t.Errorf("casillas marcadas por defecto: %d", strings.Count(body, "checked"))
	}
	form := func(kv ...string) url.Values {
		v := url.Values{"t": {"test"}, "csrf": {srv.csrf}}
		for i := 0; i < len(kv); i += 2 {
			v.Set(kv[i], kv[i+1])
		}
		return v
	}
	_, body = post(t, ts, "/prep/issue", form("action", "apply"))
	if !strings.Contains(body, "escriba un mensaje o marque al menos un dato") {
		t.Errorf("sin datos debe rechazar:\n%s", body)
	}
	_, body = post(t, ts, "/prep/issue", form("action", "apply", "message", `hola \e[2J`, "ip", "yes"))
	if !strings.Contains(body, "no use la barra invertida") {
		t.Errorf("debía rechazar la barra invertida:\n%s", body)
	}
	for _, action := range []string{"apply", "state", "restore"} {
		_, body = post(t, ts, "/prep/issue", form("action", action, "message", "Hola", "ip", "yes"))
		if !strings.Contains(body, "no se encuentra la llave privada") {
			t.Errorf("%s: debía intentar conectar:\n%s", action, body)
		}
		// Solo queda marcada la casilla enviada.
		if strings.Count(body, "checked") != 1 {
			t.Errorf("%s: casillas marcadas %d, quería 1", action, strings.Count(body, "checked"))
		}
	}
}

func TestUserForms(t *testing.T) {
	srv, ts := newTestServer(t)
	form := func(kv ...string) url.Values {
		v := url.Values{"t": {"test"}, "csrf": {srv.csrf}}
		for i := 0; i < len(kv); i += 2 {
			v.Set(kv[i], kv[i+1])
		}
		return v
	}
	// Crear: por defecto viene marcada la casilla de llaves y la contraseña deshabilitada.
	_, body := get(t, ts, "/users/create?t=test")
	if !strings.Contains(body, `id="keys" checked`) || !strings.Contains(body, `autocomplete="new-password" maxlength="72" disabled`) {
		t.Errorf("valores por defecto de crear usuario:\n%s", body)
	}
	_, body = post(t, ts, "/users/create", form("action", "create", "name", "root", "keys", "yes"))
	if !strings.Contains(body, "cuenta del sistema") {
		t.Errorf("debía rechazar root:\n%s", body)
	}
	_, body = post(t, ts, "/users/create", form("action", "create", "name", "ana"))
	if !strings.Contains(body, "indique una contraseña o marque") {
		t.Errorf("debía pedir contraseña o llaves:\n%s", body)
	}
	// La contraseña nunca se devuelve en la página.
	_, body = post(t, ts, "/users/create", form("action", "create", "name", "ana", "password", "MiClaveSecreta1"))
	if strings.Contains(body, "MiClaveSecreta1") || !strings.Contains(body, "no se encuentra la llave privada") {
		t.Errorf("la contraseña no debe volver a la página y debía intentar conectar:\n%s", body)
	}
	_, body = post(t, ts, "/users/create", form("action", "list"))
	if !strings.Contains(body, "no se encuentra la llave privada") {
		t.Errorf("listar debía intentar conectar")
	}

	// Eliminar: exige confirmación.
	_, body = post(t, ts, "/users/delete", form("action", "delete", "name", "ana"))
	if !strings.Contains(body, "Marque la casilla de confirmación") {
		t.Errorf("debía exigir confirmación:\n%s", body)
	}
	_, body = post(t, ts, "/users/delete", form("action", "delete", "name", "ana", "confirm", "yes", "remove_files", "yes"))
	if !strings.Contains(body, "no se encuentra la llave privada") || !strings.Contains(body, "checked") {
		t.Errorf("debía intentar conectar y conservar la casilla:\n%s", body)
	}
}

func TestServicesForm(t *testing.T) {
	srv, ts := newTestServer(t)
	form := func(kv ...string) url.Values {
		v := url.Values{"t": {"test"}, "csrf": {srv.csrf}}
		for i := 0; i < len(kv); i += 2 {
			v.Set(kv[i], kv[i+1])
		}
		return v
	}
	_, body := get(t, ts, "/services?t=test")
	for _, b := range []string{">start<", ">stop<", ">restart<", ">status<", ">enable<", ">disable<"} {
		if !strings.Contains(body, b) {
			t.Errorf("falta el botón %s", b)
		}
	}
	app := filepath.Join(t.TempDir(), "fecha.sh")
	os.WriteFile(app, []byte("#!/bin/bash\ndate\n"), 0o755)
	cases := []struct {
		form url.Values
		want string
	}{
		{form("action", "deploy", "name", "Catalogo!", "source", app, "type", "simple"), "nombre de servicio inválido"},
		{form("action", "deploy", "name", "fecha", "source", "fecha.sh", "type", "oneshot"), "ruta completa"},
		{form("action", "deploy", "name", "fecha", "source", app, "type", "oneshot", "args", "$(reboot)"), "argumento inválido"},
		{form("action", "deploy", "name", "fecha", "source", app, "type", "oneshot", "env", "a=b"), "variable inválida"},
		{form("action", "status", "unit", "a;b"), "Indique la unidad"},
		{form("action", "mask", "unit", "ssh"), "Acción desconocida"},
		// Datos válidos: llega al canal (aquí falla porque la llave no existe).
		{form("action", "deploy", "name", "fecha", "source", app, "type", "oneshot", "start", "yes"), "no se encuentra la llave privada"},
		{form("action", "restart", "unit", "fecha"), "no se encuentra la llave privada"},
		{form("action", "list"), "no se encuentra la llave privada"},
	}
	for _, c := range cases {
		_, body := post(t, ts, "/services", c.form)
		if !strings.Contains(body, c.want) {
			t.Errorf("%v: no contiene %q", c.form, c.want)
		}
	}
	// Tras desplegar, la unidad queda lista en el formulario de gestión.
	_, body = post(t, ts, "/services", form("action", "deploy", "name", "fecha", "source", app, "type", "oneshot"))
	if !strings.Contains(body, `id="unit" name="unit" value="fecha"`) {
		t.Errorf("el formulario de gestión debe quedar con la unidad desplegada")
	}
}
