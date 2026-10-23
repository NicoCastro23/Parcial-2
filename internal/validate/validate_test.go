package validate

import (
	"reflect"
	"strings"
	"testing"
)

// Entradas típicas de inyección de comandos: ninguna debe superar la validación.
var injections = []string{
	"vim; rm -rf /",
	"vim && id",
	"$(id)",
	"`id`",
	"vim|cat",
	"vim\nid",
	"vim id",
	"-oProxyCommand=x",
	"../etc/passwd",
	"a'b",
	`a"b`,
	"",
}

func TestPackageName(t *testing.T) {
	for _, ok := range []string{"vim", "libssl3", "g++", "python3.11", "haproxy", "openssh-server"} {
		if err := PackageName(ok); err != nil {
			t.Errorf("%q debería ser válido: %v", ok, err)
		}
	}
	for _, bad := range append([]string{"A", "-vim", "x"}, injections...) {
		if err := PackageName(bad); err == nil {
			t.Errorf("%q debería ser inválido", bad)
		}
	}
}

func TestPackageList(t *testing.T) {
	got, err := PackageList("vim, curl  htop,vim")
	if err != nil || !reflect.DeepEqual(got, []string{"vim", "curl", "htop"}) {
		t.Fatalf("got %v, %v", got, err)
	}
	if _, err := PackageList("   "); err == nil {
		t.Error("lista vacía debería fallar")
	}
	if _, err := PackageList("vim; id"); err == nil {
		t.Error("inyección debería fallar")
	}
	many := strings.Repeat("pkg ", 11)
	if _, err := PackageList(many); err == nil {
		t.Error("más de 10 paquetes debería fallar")
	}
}

func TestUsername(t *testing.T) {
	for _, ok := range []string{"carlos", "juan_c", "_svc", "user-1"} {
		if err := Username(ok); err != nil {
			t.Errorf("%q debería ser válido: %v", ok, err)
		}
	}
	for _, bad := range append([]string{"Carlos", "1abc", "-x", strings.Repeat("a", 33)}, injections...) {
		if err := Username(bad); err == nil {
			t.Errorf("%q debería ser inválido", bad)
		}
	}
}

func TestReservedUser(t *testing.T) {
	for _, u := range []string{"root", "www-data", "sshd"} {
		if !ReservedUser(u) {
			t.Errorf("%q debería ser reservado", u)
		}
	}
	if ReservedUser("miguel") {
		t.Error("miguel no es reservado")
	}
}

func TestHostname(t *testing.T) {
	for _, ok := range []string{"servidor1", "balanceador", "a", "mv-2"} {
		if err := Hostname(ok); err != nil {
			t.Errorf("%q debería ser válido: %v", ok, err)
		}
	}
	for _, bad := range append([]string{"-a", "a-", "Servidor", "a.b", "a_b", strings.Repeat("a", 64)}, injections...) {
		if err := Hostname(bad); err == nil {
			t.Errorf("%q debería ser inválido", bad)
		}
	}
}

func TestPort(t *testing.T) {
	if n, err := Port(" 8080 "); err != nil || n != 8080 {
		t.Errorf("got %d, %v", n, err)
	}
	for _, bad := range []string{"0", "65536", "-1", "80a", "", "1e3"} {
		if _, err := Port(bad); err == nil {
			t.Errorf("%q debería ser inválido", bad)
		}
	}
}

func TestAddress(t *testing.T) {
	for _, ok := range []string{"192.168.1.65", "::1", "servidor1", "vm.example.com"} {
		if err := Address(ok); err != nil {
			t.Errorf("%q debería ser válido: %v", ok, err)
		}
	}
	for _, bad := range append([]string{"a b", "-x", "a..b", "Host"}, injections...) {
		if err := Address(bad); err == nil {
			t.Errorf("%q debería ser inválido", bad)
		}
	}
}

func TestUnitName(t *testing.T) {
	cases := map[string]string{
		"libreria":         "libreria.service",
		"libreria.service": "libreria.service",
		"backup.timer":     "backup.timer",
		"getty@tty1":       "getty@tty1.service",
	}
	for in, want := range cases {
		got, err := UnitName(in)
		if err != nil || got != want {
			t.Errorf("UnitName(%q) = %q, %v; quería %q", in, got, err, want)
		}
	}
	for _, bad := range append([]string{"-x.service", "a b"}, injections...) {
		if _, err := UnitName(bad); err == nil {
			t.Errorf("%q debería ser inválido", bad)
		}
	}
}

func TestServerName(t *testing.T) {
	for _, ok := range []string{"servidor1", "web-2", "api.v1"} {
		if err := ServerName(ok); err != nil {
			t.Errorf("%q debería ser válido: %v", ok, err)
		}
	}
	for _, bad := range append([]string{"-a", strings.Repeat("a", 33)}, injections...) {
		if err := ServerName(bad); err == nil {
			t.Errorf("%q debería ser inválido", bad)
		}
	}
}

func TestIssueText(t *testing.T) {
	got, err := IssueText("  Computación en la nube 2026-2  ")
	if err != nil || got != "Computación en la nube 2026-2" {
		t.Fatalf("got %q, %v", got, err)
	}
	for _, bad := range []string{`hola \n`, "a\nb", "a\x00b", strings.Repeat("x", 201)} {
		if _, err := IssueText(bad); err == nil {
			t.Errorf("%q debería ser inválido", bad)
		}
	}
	if got, err := IssueText(""); err != nil || got != "" {
		t.Errorf("vacío debería ser válido, got %q, %v", got, err)
	}
}

func TestID(t *testing.T) {
	if err := ID("test"); err != nil {
		t.Error(err)
	}
	for _, bad := range []string{"", "A", "a b", "-a", "../x"} {
		if err := ID(bad); err == nil {
			t.Errorf("%q debería ser inválido", bad)
		}
	}
}

func TestDomain(t *testing.T) {
	for _, ok := range []string{"lab.local", "local", "uq.edu.co", "a-1.b2"} {
		if err := Domain(ok); err != nil {
			t.Errorf("%q debería ser válido: %v", ok, err)
		}
	}
	for _, bad := range append([]string{"Lab.local", ".local", "lab..local", "lab.local.", "-a.b", "a_b.c", strings.Repeat("a.", 101) + "a"}, injections...) {
		if err := Domain(bad); err == nil {
			t.Errorf("%q debería ser inválido", bad)
		}
	}
}
