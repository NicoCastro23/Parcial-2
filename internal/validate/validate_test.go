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

func TestFullName(t *testing.T) {
	for _, ok := range []string{"", "Ana María Pérez", "Juan O'Neil", "Carlos-2"} {
		if _, err := FullName(ok); err != nil {
			t.Errorf("%q debería ser válido: %v", ok, err)
		}
	}
	for _, bad := range []string{"a:b", "a,b", "a\nb", `a\b`, strings.Repeat("x", 65)} {
		if _, err := FullName(bad); err == nil {
			t.Errorf("%q debería ser inválido", bad)
		}
	}
}

func TestPassword(t *testing.T) {
	for _, ok := range []string{"12345678", "C0ntr4s3ñ@ 'larga' $(id)", strings.Repeat("x", 72)} {
		if err := Password(ok); err != nil {
			t.Errorf("%q debería ser válida: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "corta", "con\nsalto", strings.Repeat("x", 73)} {
		if err := Password(bad); err == nil {
			t.Errorf("%q debería ser inválida", bad)
		}
	}
}

func TestServiceFields(t *testing.T) {
	for _, ok := range []string{"catalogo", "fecha-hora", "app2"} {
		if err := ServiceName(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range append([]string{"ssh.service", "Catalogo", "2app", "a", strings.Repeat("a", 29)}, injections...) {
		if err := ServiceName(bad); err == nil {
			t.Errorf("servicio %q debería ser inválido", bad)
		}
	}
	for _, ok := range []string{"catalogo", "bin/app", "scripts/fecha.sh", "app-linux_amd64"} {
		if err := RelPath(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"/bin/sh", "../x", "a/../b", "a//b", "a b", "./app", "a;id", ""} {
		if err := RelPath(bad); err == nil {
			t.Errorf("ruta %q debería ser inválida", bad)
		}
	}
	if got, err := ExecArgs("  --port=8080 -addr :9000 "); err != nil || len(got) != 3 {
		t.Errorf("ExecArgs: %v %v", got, err)
	}
	for _, bad := range []string{"$HOME", "%h", "'x'", `"x"`, "a;b", "$(id)", "a|b", `a\b`} {
		if _, err := ExecArgs(bad); err == nil {
			t.Errorf("argumento %q debería ser inválido", bad)
		}
	}
	if got, err := EnvVars("PORT=8080 GIN_MODE=release DB=/opt/x/db.sqlite EMPTY="); err != nil || len(got) != 4 {
		t.Errorf("EnvVars: %v %v", got, err)
	}
	for _, bad := range []string{"port=1", "PORT", "A=$B", "A=a b", "A='x'", "1A=x"} {
		if _, err := EnvVars(bad); err == nil {
			t.Errorf("variable %q debería ser inválida", bad)
		}
	}
}
