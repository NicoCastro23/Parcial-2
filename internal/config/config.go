// Package config carga y guarda la configuración de la aplicación: dónde
// escucha el servidor web y cuáles son las máquinas virtuales (destinos) que
// administra.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"np2auto/internal/validate"
)

// Transportes de comunicación con una VM.
const (
	TransportSSH   = "ssh"   // SSH con llaves de autenticación (después de instalar SSH)
	TransportGuest = "guest" // Guest Additions vía VBoxManage guestcontrol (antes de SSH)
)

// Target describe una máquina virtual administrada por la aplicación.
type Target struct {
	ID    string `json:"id"`
	Label string `json:"label"`

	// Conexión SSH.
	Host    string `json:"host"`
	Port    int    `json:"port"`
	User    string `json:"user"`
	KeyPath string `json:"key"`

	// Transport indica qué canal se usa hoy: "ssh" o "guest".
	Transport string `json:"transport"`

	// Guest Additions. La contraseña nunca se guarda en el archivo: se lee de
	// la variable de entorno cuyo nombre está en GuestPasswordEnv.
	VMName           string `json:"vm_name"`
	GuestUser        string `json:"guest_user"`
	GuestPasswordEnv string `json:"guest_password_env"`
}

// Config es el contenido del archivo config.json.
type Config struct {
	Listen     string   `json:"listen"`
	DataDir    string   `json:"data_dir"`
	VBoxManage string   `json:"vboxmanage"`
	Targets    []Target `json:"targets"`
}

// Default devuelve una configuración inicial coherente con el escenario del
// curso (red en modo puente 192.168.1.0/24). Es solo un punto de partida:
// el usuario debe ajustar IP, nombres de VM y rutas de llaves.
func Default() Config {
	return Config{
		Listen:     "127.0.0.1:8088",
		DataDir:    "data",
		VBoxManage: "VBoxManage",
		Targets: []Target{
			{
				ID: "test", Label: "VM de pruebas",
				Host: "192.168.1.65", Port: 22, User: "root",
				KeyPath:   "~/.ssh/np2_test_root",
				Transport: TransportGuest,
				VMName:    "mv1", GuestUser: "miguel", GuestPasswordEnv: "NP2_GUEST_PASSWORD_TEST",
			},
			{
				ID: "balancer", Label: "VM del balanceador (HAProxy)",
				Host: "192.168.1.68", Port: 22, User: "root",
				KeyPath:   "~/.ssh/id_lab",
				Transport: TransportSSH,
				VMName:    "balanceador", GuestUser: "miguel", GuestPasswordEnv: "NP2_GUEST_PASSWORD_BALANCER",
			},
		},
	}
}

// Validate comprueba que la configuración sea utilizable.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Listen) == "" {
		return errors.New("listen no puede estar vacío")
	}
	if len(c.Targets) == 0 {
		return errors.New("debe haber al menos un destino en targets")
	}
	seen := map[string]bool{}
	for _, t := range c.Targets {
		if err := validate.ID(t.ID); err != nil {
			return fmt.Errorf("destino %q: %w", t.ID, err)
		}
		if seen[t.ID] {
			return fmt.Errorf("destino %q repetido", t.ID)
		}
		seen[t.ID] = true
		if err := validate.Address(t.Host); err != nil {
			return fmt.Errorf("destino %q: %w", t.ID, err)
		}
		if t.Port < 1 || t.Port > 65535 {
			return fmt.Errorf("destino %q: puerto %d inválido", t.ID, t.Port)
		}
		if err := validate.Username(t.User); err != nil {
			return fmt.Errorf("destino %q: usuario SSH: %w", t.ID, err)
		}
		switch t.Transport {
		case TransportSSH, TransportGuest:
		default:
			return fmt.Errorf("destino %q: transport debe ser %q o %q", t.ID, TransportSSH, TransportGuest)
		}
		if t.GuestUser != "" {
			if err := validate.Username(t.GuestUser); err != nil {
				return fmt.Errorf("destino %q: guest_user: %w", t.ID, err)
			}
		}
	}
	return nil
}

// Store protege la configuración en memoria y la persiste en disco.
type Store struct {
	mu   sync.RWMutex
	path string
	cfg  Config
}

// Load lee el archivo de configuración. Si no existe lo crea con los valores
// por defecto y devuelve created=true.
func Load(path string) (s *Store, created bool, err error) {
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		s = &Store{path: path, cfg: Default()}
		if err := s.save(); err != nil {
			return nil, false, err
		}
		return s, true, nil
	case err != nil:
		return nil, false, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, false, fmt.Errorf("%s: %w", path, err)
	}
	if cfg.VBoxManage == "" {
		cfg.VBoxManage = "VBoxManage"
	}
	if cfg.DataDir == "" {
		cfg.DataDir = "data"
	}
	if err := cfg.Validate(); err != nil {
		return nil, false, fmt.Errorf("%s: %w", path, err)
	}
	return &Store{path: path, cfg: cfg}, false, nil
}

// Snapshot devuelve una copia de la configuración actual.
func (s *Store) Snapshot() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := s.cfg
	c.Targets = append([]Target(nil), s.cfg.Targets...)
	return c
}

// Target busca un destino por su ID.
func (s *Store) Target(id string) (Target, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.cfg.Targets {
		if t.ID == id {
			return t, true
		}
	}
	return Target{}, false
}

// Update modifica un destino y guarda el archivo. Si la nueva configuración
// no es válida, no se aplica.
func (s *Store) Update(id string, fn func(*Target)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.cfg
	next.Targets = append([]Target(nil), s.cfg.Targets...)
	found := false
	for i := range next.Targets {
		if next.Targets[i].ID == id {
			fn(&next.Targets[i])
			found = true
		}
	}
	if !found {
		return fmt.Errorf("destino %q no existe", id)
	}
	if err := next.Validate(); err != nil {
		return err
	}
	prev := s.cfg
	s.cfg = next
	if err := s.save(); err != nil {
		s.cfg = prev
		return err
	}
	return nil
}

// save escribe el archivo de forma atómica (archivo temporal + renombrar).
func (s *Store) save() error {
	data, err := json.MarshalIndent(s.cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".config-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

// ExpandHome reemplaza un "~" inicial por el directorio personal.
func ExpandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}
