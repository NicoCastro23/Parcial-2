package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadCreatesDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	s, created, err := Load(path)
	if err != nil || !created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	if got := len(s.Snapshot().Targets); got != 2 {
		t.Errorf("targets = %d", got)
	}
	// La segunda carga lee el archivo existente.
	s2, created, err := Load(path)
	if err != nil || created || len(s2.Snapshot().Targets) != 2 {
		t.Fatalf("created=%v err=%v", created, err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Errorf("permisos = %v, quería 0600", st.Mode().Perm())
	}
}

func TestUpdatePersistsAndValidates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	s, _, _ := Load(path)
	if err := s.Update("test", func(t *Target) { t.Transport = TransportSSH; t.KeyPath = "/k" }); err != nil {
		t.Fatal(err)
	}
	s2, _, _ := Load(path)
	got, _ := s2.Target("test")
	if got.Transport != TransportSSH || got.KeyPath != "/k" {
		t.Errorf("no se persistió: %+v", got)
	}
	// Un valor inválido no se aplica ni se guarda.
	if err := s.Update("test", func(t *Target) { t.Host = "no es un host!" }); err == nil {
		t.Error("debería rechazar el host inválido")
	}
	if cur, _ := s.Target("test"); cur.Host != "192.168.1.65" {
		t.Errorf("se aplicó un cambio inválido: %+v", cur)
	}
	if err := s.Update("nada", func(*Target) {}); err == nil {
		t.Error("destino inexistente debería fallar")
	}
}

func TestValidate(t *testing.T) {
	c := Default()
	c.Targets[0].Transport = "telnet"
	if err := c.Validate(); err == nil {
		t.Error("transporte inválido debería fallar")
	}
	c = Default()
	c.Targets[1].ID = c.Targets[0].ID
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "repetido") {
		t.Errorf("ID repetido: %v", err)
	}
	c = Default()
	c.Targets[0].Host = "-oProxyCommand=x"
	if err := c.Validate(); err == nil {
		t.Error("host con forma de opción debería fallar")
	}
}

func TestExpandHome(t *testing.T) {
	t.Setenv("HOME", "/home/u")
	if got := ExpandHome("~/.ssh/k"); got != "/home/u/.ssh/k" {
		t.Errorf("got %q", got)
	}
	if got := ExpandHome("/abs/k"); got != "/abs/k" {
		t.Errorf("got %q", got)
	}
}
