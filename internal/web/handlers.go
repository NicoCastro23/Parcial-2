package web

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"strings"
	"time"

	"np2auto/internal/config"
	"np2auto/internal/ops"
	"np2auto/internal/runner"
	"np2auto/internal/validate"
)

// navItem y navSection arman el menú lateral.
type navItem struct {
	Title string
	Path  string
	Done  bool // el módulo ya está implementado
}

type navSection struct {
	Title string
	Items []navItem
}

var nav = []navSection{
	{"General", []navItem{
		{"Conexión con las VMs", "/connection", true},
		{"Registro de operaciones", "/journal", true},
	}},
	{"Preparación del sistema", []navItem{
		{"Instalar y eliminar aplicaciones", "/prep/packages", true},
		{"Llave SSH del usuario root", "/prep/rootkey", true},
		{"Pantalla de entrada (/etc/issue)", "/m/issue", false},
		{"Nombre de host y /etc/hosts", "/prep/hostname", true},
	}},
	{"Gestión de usuarios", []navItem{
		{"Crear usuarios", "/m/users-create", false},
		{"Eliminar usuarios", "/m/users-delete", false},
	}},
	{"Servicios", []navItem{
		{"Demonios con systemd", "/m/services", false},
		{"Balanceador HAProxy", "/m/haproxy", false},
	}},
}

// pendingModule describe lo que exige el enunciado de un módulo aún no hecho.
type pendingModule struct {
	Title, Ref, Summary string
}

var pending = map[string]pendingModule{
	"issue":        {"Pantalla de entrada (/etc/issue)", "3.1.3", "Establecer /etc/issue con opciones para mostrar nombre de host, fecha, hora y dirección IP, más un mensaje personalizado."},
	"users-create": {"Crear usuarios", "3.2.1", "Crear un usuario con casilla de sudo y casilla para generar llaves (instalar la pública, descargar la privada y deshabilitar login con contraseña)."},
	"users-delete": {"Eliminar usuarios", "3.2.2", "Eliminar un usuario, con casilla para borrar también todos sus archivos."},
	"services":     {"Demonios con systemd", "3.3", "Configurar una aplicación como servicio (transferir archivos, permisos) con botones start, stop, restart, status, enable y disable."},
	"haproxy":      {"Balanceador HAProxy", "3.4", "Agregar un servidor al backend del balanceador y eliminarlo."},
}

// page es el modelo común de todas las plantillas.
type page struct {
	Title    string
	Active   string
	Nav      []navSection
	Targets  []config.Target
	Cur      config.Target
	CSRF     string
	Flash    string
	FlashErr string

	// Específicos de cada página.
	TestOutput  string
	TestOK      *bool
	Root        *ops.RootKeyResult
	DownloadURL string
	Entries     []runner.Entry
	Pending     *pendingModule

	// Módulos que usan ops.Result (resultado por pasos) y un formulario.
	Op   *ops.Result
	Form map[string]string
}

func (s *Server) newPage(r *http.Request, title, active string) (page, bool) {
	snap := s.cfg.Snapshot()
	id := r.FormValue("t")
	cur := snap.Targets[0]
	for _, t := range snap.Targets {
		if t.ID == id {
			cur = t
		}
	}
	return page{
		Title: title, Active: active, Nav: nav,
		Targets: snap.Targets, Cur: cur, CSRF: s.csrf,
	}, true
}

func (s *Server) render(w http.ResponseWriter, name string, p page) {
	var buf bytes.Buffer
	if err := s.tmpl[name].ExecuteTemplate(&buf, "layout", p); err != nil {
		s.logf("render %s: %v", name, err)
		http.Error(w, "error interno al generar la página", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	buf.WriteTo(w)
}

// ---- Conexión ----

func (s *Server) handleConnection(w http.ResponseWriter, r *http.Request) {
	p, _ := s.newPage(r, "Conexión con las VMs", "/connection")
	s.render(w, "connection", p)
}

const probeScript = `
echo "usuario: $(id -un) (uid $(id -u))"
echo "host: $(hostname)"
. /etc/os-release && echo "sistema: $PRETTY_NAME"
echo "ip: $(hostname -I 2>/dev/null)"
if command -v sshd >/dev/null 2>&1; then echo "sshd: instalado"; else echo "sshd: NO instalado"; fi
echo "servicio ssh: $(systemctl is-active ssh 2>/dev/null || echo desconocido)"
`

func (s *Server) handleConnectionTest(w http.ResponseWriter, r *http.Request) {
	p, _ := s.newPage(r, "Conexión con las VMs", "/connection")
	rn, err := s.runnerFor(p.Cur)
	if err != nil {
		p.FlashErr = err.Error()
		s.render(w, "connection", p)
		return
	}
	ctx, cancel := opContext(r, 90*time.Second)
	defer cancel()
	res, err := rn.Run(runner.WithOp(ctx, "conexion/probar"), probeScript)
	ok := err == nil
	p.TestOK = &ok
	p.TestOutput = res.Stdout
	if err != nil {
		p.FlashErr = runner.Explain(err)
		p.TestOutput = "$ " + res.Command + "\n" + res.Stdout + res.Stderr
	} else {
		p.Flash = "La VM respondió correctamente por " + rn.Describe() + "."
	}
	s.render(w, "connection", p)
}

func (s *Server) handleTransport(w http.ResponseWriter, r *http.Request) {
	p, _ := s.newPage(r, "Conexión con las VMs", "/connection")
	transport := r.PostFormValue("transport")
	err := s.cfg.Update(p.Cur.ID, func(t *config.Target) { t.Transport = transport })
	if err != nil {
		p.FlashErr = err.Error()
	} else {
		p.Flash = "Canal de comunicación actualizado."
		p.Cur, _ = s.cfg.Target(p.Cur.ID)
		p.Targets = s.cfg.Snapshot().Targets
	}
	s.render(w, "connection", p)
}

// ---- Llave SSH de root (3.1.2) ----

func (s *Server) handleRootKey(w http.ResponseWriter, r *http.Request) {
	p, _ := s.newPage(r, "Llave SSH del usuario root", "/prep/rootkey")
	s.render(w, "rootkey", p)
}

func (s *Server) handleRootKeyRun(w http.ResponseWriter, r *http.Request) {
	p, _ := s.newPage(r, "Llave SSH del usuario root", "/prep/rootkey")
	if r.PostFormValue("confirm") != "yes" {
		p.FlashErr = "Marque la casilla de confirmación: esta operación deshabilita el acceso por contraseña en la VM."
		s.render(w, "rootkey", p)
		return
	}
	unlock, ok := s.locks.try(p.Cur.ID)
	if !ok {
		p.FlashErr = "Ya hay una operación en curso sobre esta VM. Espere a que termine."
		s.render(w, "rootkey", p)
		return
	}
	defer unlock()

	rn, err := s.runnerFor(p.Cur)
	if err != nil {
		p.FlashErr = err.Error()
		s.render(w, "rootkey", p)
		return
	}
	ctx, cancel := opContext(r, 15*time.Minute)
	defer cancel()
	res := ops.ConfigureRootKey(ctx, s.operationEnv(p.Cur, rn))
	p.Root = res
	if res.OK {
		tok := s.dl.Add(res.KeyPath, res.DownloadName, 15*time.Minute)
		p.DownloadURL = "/download/" + tok
		p.Cur, _ = s.cfg.Target(p.Cur.ID) // ya cambió a SSH con la nueva llave
		p.Targets = s.cfg.Snapshot().Targets
	}
	s.render(w, "rootkey", p)
}

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	tok := cleanToken(r.PathValue("token"))
	e, ok := s.dl.Get(tok)
	if tok == "" || !ok {
		http.Error(w, "enlace de descarga inválido o vencido: ejecute de nuevo la operación", http.StatusNotFound)
		return
	}
	data, err := os.ReadFile(e.path)
	if err != nil {
		http.Error(w, "no se pudo leer la llave", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+e.name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Write(data)
}

// ---- Operaciones por pasos (módulos 3.1.1, 3.1.3, 3.1.4, 3.2, 3.3, 3.4) ----

// runOp ejecuta una operación sobre la VM elegida con las mismas reglas para
// todos los módulos: una operación a la vez por VM, el canal actual (Guest
// Additions o SSH) y un límite de tiempo propio. Deja el resultado en p.Op y
// el mensaje general en p.Flash o p.FlashErr.
func (s *Server) runOp(r *http.Request, p *page, timeout time.Duration, okMsg string, fn func(ctx context.Context, rn runner.Runner) *ops.Result) {
	unlock, ok := s.locks.try(p.Cur.ID)
	if !ok {
		p.FlashErr = "Ya hay una operación en curso sobre esta VM. Espere a que termine."
		return
	}
	defer unlock()
	rn, err := s.runnerFor(p.Cur)
	if err != nil {
		p.FlashErr = err.Error()
		return
	}
	ctx, cancel := opContext(r, timeout)
	defer cancel()
	p.Op = fn(ctx, rn)
	if p.Op.OK {
		p.Flash = okMsg
	} else {
		p.FlashErr = "La operación no se completó. Revise el paso marcado con ✗; su detalle técnico queda también en el Registro de operaciones."
	}
}

// formValues copia los campos indicados del formulario para volver a
// mostrarlos en la página.
func formValues(r *http.Request, keys ...string) map[string]string {
	m := make(map[string]string, len(keys))
	for _, k := range keys {
		m[k] = strings.TrimSpace(r.PostFormValue(k))
	}
	return m
}

// ---- Instalar y eliminar aplicaciones (3.1.1) ----

func (s *Server) handlePackages(w http.ResponseWriter, r *http.Request) {
	p, _ := s.newPage(r, "Instalar y eliminar aplicaciones", "/prep/packages")
	s.render(w, "packages", p)
}

func (s *Server) handlePackagesRun(w http.ResponseWriter, r *http.Request) {
	p, _ := s.newPage(r, "Instalar y eliminar aplicaciones", "/prep/packages")
	p.Form = formValues(r, "packages", "purge", "action")
	pkgs, err := validate.PackageList(strings.ToLower(p.Form["packages"]))
	if err != nil {
		p.FlashErr = err.Error()
		s.render(w, "packages", p)
		return
	}
	switch action := p.Form["action"]; action {
	case "state":
		s.runOp(r, &p, 2*time.Minute, "Estado consultado.", func(ctx context.Context, rn runner.Runner) *ops.Result {
			return ops.PackagesState(ctx, rn, pkgs)
		})
	case ops.PkgInstall, ops.PkgRemove:
		in := ops.PackagesInput{Action: action, Packages: pkgs, Purge: p.Form["purge"] == "yes"}
		msg := "Instalación completada: " + strings.Join(pkgs, ", ") + "."
		if action == ops.PkgRemove {
			msg = "Eliminación completada: " + strings.Join(pkgs, ", ") + "."
		}
		s.runOp(r, &p, 30*time.Minute, msg, func(ctx context.Context, rn runner.Runner) *ops.Result {
			return ops.ManagePackages(ctx, rn, in)
		})
	default:
		p.FlashErr = "Acción desconocida: use Instalar, Eliminar o Consultar estado."
	}
	s.render(w, "packages", p)
}

// ---- Nombre de host y /etc/hosts (3.1.4) ----

func (s *Server) handleHostname(w http.ResponseWriter, r *http.Request) {
	p, _ := s.newPage(r, "Nombre de host y /etc/hosts", "/prep/hostname")
	s.render(w, "hostname", p)
}

func (s *Server) handleHostnameRun(w http.ResponseWriter, r *http.Request) {
	p, _ := s.newPage(r, "Nombre de host y /etc/hosts", "/prep/hostname")
	p.Form = formValues(r, "name", "domain", "action")
	if p.Form["action"] == "state" {
		s.runOp(r, &p, 2*time.Minute, "Estado actual consultado.", func(ctx context.Context, rn runner.Runner) *ops.Result {
			return ops.HostnameState(ctx, rn)
		})
		s.render(w, "hostname", p)
		return
	}
	in := ops.HostnameInput{Name: strings.ToLower(p.Form["name"]), Domain: strings.ToLower(p.Form["domain"])}
	if err := in.Validate(); err != nil {
		p.FlashErr = err.Error()
		s.render(w, "hostname", p)
		return
	}
	s.runOp(r, &p, 5*time.Minute, "Nombre de host asignado y /etc/hosts actualizado.", func(ctx context.Context, rn runner.Runner) *ops.Result {
		return ops.SetHostname(ctx, rn, in)
	})
	s.render(w, "hostname", p)
}

// ---- Registro y módulos pendientes ----

func (s *Server) handleJournal(w http.ResponseWriter, r *http.Request) {
	p, _ := s.newPage(r, "Registro de operaciones", "/journal")
	entries, err := s.journal.Tail(50)
	if err != nil {
		p.FlashErr = "No se pudo leer el registro: " + err.Error()
	}
	p.Entries = entries
	s.render(w, "journal", p)
}

func (s *Server) handlePending(w http.ResponseWriter, r *http.Request) {
	m, ok := pending[r.PathValue("slug")]
	if !ok {
		http.NotFound(w, r)
		return
	}
	p, _ := s.newPage(r, m.Title, "/m/"+r.PathValue("slug"))
	p.Pending = &m
	s.render(w, "pending", p)
}
