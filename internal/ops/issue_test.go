package ops

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestIssueContent(t *testing.T) {
	in := IssueInput{Message: "Bienvenido al laboratorio", Color: true, Hostname: true, IP: true, Date: true, Time: true}
	want := "\n" +
		`  \e{bold}\e{cyan}Bienvenido al laboratorio\e{reset}` + "\n\n" +
		`  Equipo:       \n` + "\n" +
		`  Fecha:        \d` + "\n" +
		`  Hora:         \t` + "\n" +
		`  Dirección IP: \4` + "\n\n"
	if got := in.Content(); got != want {
		t.Errorf("contenido:\n%q\nquería:\n%q", got, want)
	}
	if got := (IssueInput{Message: "Hola"}).Content(); got != "\n  Hola\n\n" {
		t.Errorf("solo mensaje: %q", got)
	}
	if got := (IssueInput{TTY: true}).Content(); got != "\n  Terminal: \\l\n\n" {
		t.Errorf("solo casilla: %q", got)
	}
}

func TestIssueValidate(t *testing.T) {
	if err := (IssueInput{}).Validate(); err == nil {
		t.Error("sin mensaje ni casillas debe fallar")
	}
	for _, bad := range []string{`hola \n`, "a\nb", strings.Repeat("x", 201)} {
		if err := (IssueInput{Message: bad, Hostname: true}).Validate(); err == nil {
			t.Errorf("%q debería ser inválido", bad)
		}
	}
	for _, ok := range []IssueInput{{Message: "Hola 'mundo' $(id) ; `x` ñandú"}, {IP: true}} {
		if err := ok.Validate(); err != nil {
			t.Errorf("%+v debería ser válido: %v", ok, err)
		}
	}
}

func TestSetIssueFlow(t *testing.T) {
	in := IssueInput{Message: "Hola", Hostname: true}
	f := &fakeRunner{stdout: map[string]string{
		"issue/antes":     "Debian GNU/Linux 13 \\n \\l\n\n",
		"issue/verificar": in.Content(),
		"issue/vista":     "\r\n  Hola\r\n\r\n  Equipo: web1\r\n",
	}}
	res := SetIssue(context.Background(), f, in)
	if !res.OK {
		t.Fatalf("debería terminar bien: %+v", res.Steps)
	}
	want := "issue/antes,issue/escribir,issue/verificar,issue/vista"
	if got := strings.Join(f.ops, ","); got != want {
		t.Errorf("pasos %s; quería %s", got, want)
	}
	if res.Preview != "  Hola\n\n  Equipo: web1" {
		t.Errorf("vista previa: %q", res.Preview)
	}
	if res.Steps[0].Detail != `Debian GNU/Linux 13 \n \l` {
		t.Errorf("estado anterior: %q", res.Steps[0].Detail)
	}
}

func TestSetIssueDetectsMismatch(t *testing.T) {
	f := &fakeRunner{stdout: map[string]string{"issue/verificar": "otra cosa\n"}}
	res := SetIssue(context.Background(), f, IssueInput{Message: "Hola"})
	if res.OK || !strings.Contains(res.Steps[len(res.Steps)-1].Detail, "no coincide") {
		t.Fatalf("debe detectar que el contenido no coincide: %+v", res.Steps)
	}
}

func TestSetIssueRejectsInvalid(t *testing.T) {
	f := &fakeRunner{}
	if res := SetIssue(context.Background(), f, IssueInput{Message: `\e[2J`}); res.OK || len(f.ops) != 0 {
		t.Error("no debe ejecutar nada en la VM con un mensaje inválido")
	}
}

// TestIssueScripts ejecuta con bash los scripts reales de escritura y
// restauración sobre un archivo temporal.
func TestIssueScripts(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash no disponible")
	}
	p := filepath.Join(t.TempDir(), "issue")
	orig := "Debian GNU/Linux 13 \\n \\l\n\n"
	os.WriteFile(p, []byte(orig), 0o644)
	run := func(script string) string {
		out, err := exec.Command("bash", "-c", "set -eu\n"+script).CombinedOutput()
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		return string(out)
	}
	// Un mensaje con comillas y $ no debe romper ni ejecutar nada.
	c1 := IssueInput{Message: "Hola 'equipo' $(id) `id`", Hostname: true, Color: true}.Content()
	run(issueWriteScript(p, c1))
	if got, _ := os.ReadFile(p); string(got) != c1 {
		t.Fatalf("escritura 1:\n%q\nquería\n%q", got, c1)
	}
	c2 := IssueInput{IP: true}.Content()
	run(issueWriteScript(p, c2))
	if got, _ := os.ReadFile(p); string(got) != c2 {
		t.Fatalf("escritura 2: %q", got)
	}
	if got, _ := os.ReadFile(p + ".np2-orig"); string(got) != orig {
		t.Errorf("el original debe conservarse tras varios cambios: %q", got)
	}
	if got, _ := os.ReadFile(p + ".np2-prev"); string(got) != c1 {
		t.Errorf("la copia anterior debe ser la versión previa: %q", got)
	}
	run(issueRestoreScript(p))
	if got, _ := os.ReadFile(p); string(got) != orig {
		t.Errorf("restaurar: %q", got)
	}
	// Sin original guardado, restaurar falla con un mensaje claro.
	q := filepath.Join(t.TempDir(), "issue")
	os.WriteFile(q, []byte(orig), 0o644)
	out, err := exec.Command("bash", "-c", "set -eu\n"+issueRestoreScript(q)).CombinedOutput()
	if err == nil || !strings.Contains(string(out), "no hay copia del original") {
		t.Errorf("debía fallar sin original: %v %s", err, out)
	}
}

// TestIssueRendersWithAgetty muestra el contenido generado con el agetty real
// (solo lectura) para comprobar que las secuencias de escape son válidas.
func TestIssueRendersWithAgetty(t *testing.T) {
	for _, bin := range []string{"agetty", "script", "timeout"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skip(bin + " no disponible")
		}
	}
	host, _ := os.Hostname()
	p := filepath.Join(t.TempDir(), "issue")
	in := IssueInput{Message: "Bienvenido", Color: true, Hostname: true, Date: true, Time: true, IP: true, System: true, Kernel: true, TTY: true, Users: true}
	os.WriteFile(p, []byte(in.Content()), 0o644)
	out, err := exec.Command("timeout", "10", "script", "-qec", "agetty --show-issue -f "+p, "/dev/null").Output()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	got := cleanTerminal(string(out))
	t.Logf("\n%s", got)
	if strings.Contains(got, `\`) || strings.Contains(got, "{") {
		t.Errorf("quedaron secuencias sin interpretar:\n%s", got)
	}
	for _, want := range []string{"Bienvenido", "Equipo:", host, "Terminal:"} {
		if !strings.Contains(got, want) {
			t.Errorf("falta %q en:\n%s", want, got)
		}
	}
}
