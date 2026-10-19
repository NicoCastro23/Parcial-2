// Package web implementa la consola web: navegación por módulos, formularios
// con validación y presentación de resultados.
package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"np2auto/internal/config"
	"np2auto/internal/ops"
	"np2auto/internal/runner"
)

//go:embed templates/*.html static/*
var assets embed.FS

// Server es el servidor HTTP de la aplicación.
type Server struct {
	cfg     *config.Store
	journal *runner.Journal
	dataDir string
	tmpl    map[string]*template.Template
	csrf    string
	dl      *downloadStore
	locks   *lockSet
	handler http.Handler
}

// New construye el servidor. Crea el directorio de datos si no existe.
func New(cfg *config.Store) (*Server, error) {
	snap := cfg.Snapshot()
	dataDir, err := filepath.Abs(snap.DataDir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	j, err := runner.NewJournal(filepath.Join(dataDir, "logs", "operaciones.jsonl"))
	if err != nil {
		return nil, err
	}
	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		return nil, err
	}
	s := &Server{
		cfg: cfg, journal: j, dataDir: dataDir,
		csrf: hex.EncodeToString(token),
		dl:   newDownloadStore(), locks: newLockSet(),
		tmpl: map[string]*template.Template{},
	}
	for _, name := range []string{"connection", "rootkey", "pending", "journal"} {
		t, err := template.ParseFS(assets, "templates/layout.html", "templates/"+name+".html")
		if err != nil {
			return nil, fmt.Errorf("plantilla %s: %w", name, err)
		}
		s.tmpl[name] = t
	}

	static, err := fs.Sub(assets, "static")
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/connection", http.StatusSeeOther)
	})
	mux.HandleFunc("GET /connection", s.handleConnection)
	mux.HandleFunc("POST /connection/test", s.handleConnectionTest)
	mux.HandleFunc("POST /connection/transport", s.handleTransport)
	mux.HandleFunc("GET /prep/rootkey", s.handleRootKey)
	mux.HandleFunc("POST /prep/rootkey", s.handleRootKeyRun)
	mux.HandleFunc("GET /download/{token}", s.handleDownload)
	mux.HandleFunc("GET /journal", s.handleJournal)
	mux.HandleFunc("GET /m/{slug}", s.handlePending)

	s.handler = s.guard(snap.Listen, mux)
	return s, nil
}

// Handler devuelve el http.Handler listo para servir.
func (s *Server) Handler() http.Handler { return s.handler }

// guard aplica las protecciones comunes: la aplicación ejecuta comandos como
// root en las VMs, así que se limita quién puede hablarle.
//   - Si escucha en loopback, solo acepta peticiones cuyo Host sea
//     localhost/127.0.0.1/::1 (evita DNS rebinding desde otras páginas).
//   - Toda petición POST debe traer el token CSRF de la sesión del proceso.
func (s *Server) guard(listen string, next http.Handler) http.Handler {
	host, port, _ := net.SplitHostPort(listen)
	loopback := host == "127.0.0.1" || host == "localhost" || host == "::1"
	allowed := map[string]bool{}
	if loopback {
		for _, h := range []string{"localhost", "127.0.0.1", "[::1]"} {
			allowed[h+":"+port] = true
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if loopback && !allowed[r.Host] {
			http.Error(w, "Host no permitido", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
			if err := r.ParseForm(); err != nil {
				http.Error(w, "formulario inválido", http.StatusBadRequest)
				return
			}
			if subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf")), []byte(s.csrf)) != 1 {
				http.Error(w, "token CSRF inválido; recargue la página", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// runnerFor crea el Runner del destino según su transporte actual y lo
// envuelve para registrar cada ejecución.
func (s *Server) runnerFor(t config.Target) (runner.Runner, error) {
	var rn runner.Runner
	switch t.Transport {
	case config.TransportSSH:
		if t.KeyPath == "" {
			return nil, fmt.Errorf("el destino %q no tiene una llave configurada (campo \"key\")", t.ID)
		}
		key := config.ExpandHome(t.KeyPath)
		if _, err := os.Stat(key); err != nil {
			return nil, fmt.Errorf("no se encuentra la llave privada %s: configure \"key\" o use el módulo de la llave SSH de root", key)
		}
		rn = &runner.SSH{
			Host: t.Host, Port: t.Port, User: t.User, KeyPath: key,
			KnownHosts: filepath.Join(s.dataDir, "known_hosts"),
		}
	case config.TransportGuest:
		if t.VMName == "" || t.GuestUser == "" {
			return nil, fmt.Errorf("el destino %q necesita vm_name y guest_user para usar Guest Additions", t.ID)
		}
		rn = &runner.Guest{
			VBoxManage: s.cfg.Snapshot().VBoxManage,
			VM:         t.VMName, User: t.GuestUser,
			Password: os.Getenv(t.GuestPasswordEnv),
		}
	default:
		return nil, fmt.Errorf("transporte desconocido %q", t.Transport)
	}
	return runner.Journaled{Runner: rn, J: s.journal, Target: t.ID}, nil
}

// operationEnv prepara el entorno de una operación sobre un destino.
func (s *Server) operationEnv(t config.Target, rn runner.Runner) ops.Env {
	return ops.Env{
		Target: t, Runner: rn, DataDir: s.dataDir,
		KnownHosts: filepath.Join(s.dataDir, "known_hosts"),
		OnSuccess: func(keyPath string) error {
			return s.cfg.Update(t.ID, func(x *config.Target) {
				x.Transport = config.TransportSSH
				x.User = "root"
				x.KeyPath = keyPath
			})
		},
	}
}

// opContext devuelve un contexto con límite de tiempo que NO se cancela si el
// navegador se desconecta: una operación a medias (por ejemplo, entre
// endurecer SSH y verificarlo) es más peligrosa que una que termina sola.
func opContext(r *http.Request, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(r.Context()), d)
}

// ---- descargas de llaves privadas ----

type dlEntry struct {
	path, name string
	expires    time.Time
}

type downloadStore struct {
	mu sync.Mutex
	m  map[string]dlEntry
}

func newDownloadStore() *downloadStore { return &downloadStore{m: map[string]dlEntry{}} }

func (d *downloadStore) Add(path, name string, ttl time.Duration) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	tok := hex.EncodeToString(b)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.purge()
	d.m[tok] = dlEntry{path: path, name: name, expires: time.Now().Add(ttl)}
	return tok
}

func (d *downloadStore) Get(tok string) (dlEntry, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.purge()
	e, ok := d.m[tok]
	return e, ok
}

func (d *downloadStore) purge() {
	now := time.Now()
	for k, e := range d.m {
		if now.After(e.expires) {
			delete(d.m, k)
		}
	}
}

// ---- exclusión mutua por destino ----

type lockSet struct {
	mu sync.Mutex
	m  map[string]*sync.Mutex
}

func newLockSet() *lockSet { return &lockSet{m: map[string]*sync.Mutex{}} }

// try intenta bloquear el destino; si hay otra operación en curso devuelve false.
func (l *lockSet) try(id string) (unlock func(), ok bool) {
	l.mu.Lock()
	mu, found := l.m[id]
	if !found {
		mu = &sync.Mutex{}
		l.m[id] = mu
	}
	l.mu.Unlock()
	if !mu.TryLock() {
		return nil, false
	}
	return mu.Unlock, true
}

func (s *Server) logf(format string, args ...any) { log.Printf(format, args...) }

// cleanToken evita que un token con separadores llegue al sistema de archivos.
func cleanToken(tok string) string {
	if strings.ContainsAny(tok, "/\\.") {
		return ""
	}
	return tok
}
