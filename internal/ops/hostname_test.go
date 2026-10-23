package ops

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"np2auto/internal/runner"
)

// fakeRunner simula la VM: guarda los scripts recibidos y responde según la
// etiqueta de la sub-operación (runner.WithOp).
type fakeRunner struct {
	ops     []string
	scripts []string
	failOn  string            // sub-operación que debe fallar, p. ej. "hostname/hosts"
	stdout  map[string]string // salida simulada por sub-operación
	upload  []byte            // lo recibido por RunInput (transferencias)
}

func (f *fakeRunner) RunInput(ctx context.Context, script string, in io.Reader) (runner.Result, error) {
	b, err := io.ReadAll(in)
	if err != nil {
		return runner.Result{}, err
	}
	f.upload = b
	return f.Run(ctx, script)
}

func (f *fakeRunner) Transport() string { return "ssh" }
func (f *fakeRunner) Describe() string  { return "fake" }
func (f *fakeRunner) Run(ctx context.Context, script string) (runner.Result, error) {
	op := runner.OpFrom(ctx)
	f.ops = append(f.ops, op)
	f.scripts = append(f.scripts, script)
	r := runner.Result{Command: "fake", Script: script, Stdout: f.stdout[op]}
	if op == f.failOn {
		r.ExitCode = 1
		r.Stderr = "fallo simulado"
		return r, &runner.Error{Kind: runner.KindExit, Result: r, Err: errors.New("exit status 1")}
	}
	return r, nil
}

func TestSetHostnameFlow(t *testing.T) {
	f := &fakeRunner{stdout: map[string]string{
		"hostname/antes":     "nombre de host: debian\n/etc/hostname: debian\n/etc/hosts: 127.0.1.1\tdebian\n",
		"hostname/verificar": "nombre de host: web1\n",
	}}
	res := SetHostname(context.Background(), f, HostnameInput{Name: "web1", Domain: "lab.local"})
	if !res.OK {
		t.Fatalf("debería terminar bien: %+v", res.Steps)
	}
	want := []string{"hostname/antes", "hostname/asignar", "hostname/hosts", "hostname/verificar"}
	if strings.Join(f.ops, ",") != strings.Join(want, ",") {
		t.Errorf("pasos %v; quería %v", f.ops, want)
	}
	if !strings.Contains(f.scripts[2], `entry='web1.lab.local web1'`) {
		t.Errorf("la entrada de /etc/hosts no es la esperada:\n%s", f.scripts[2])
	}
	last := res.Steps[len(res.Steps)-1].Detail
	if !strings.Contains(last, "Antes: debian") || !strings.Contains(last, "Después: web1") {
		t.Errorf("el resumen debe mostrar antes y después: %q", last)
	}
}

func TestSetHostnameStopsOnFailure(t *testing.T) {
	f := &fakeRunner{failOn: "hostname/asignar"}
	res := SetHostname(context.Background(), f, HostnameInput{Name: "web1"})
	if res.OK || len(f.ops) != 2 {
		t.Fatalf("debe detenerse en el paso que falla: ok=%v ops=%v", res.OK, f.ops)
	}
	s := res.Steps[len(res.Steps)-1]
	if s.OK || !strings.Contains(s.Detail, "fallo simulado") || !strings.Contains(s.Technical, "código de salida 1") {
		t.Errorf("el paso fallido debe explicar el error y conservar el detalle técnico: %+v", s)
	}
}

func TestSetHostnameRejectsInvalidInput(t *testing.T) {
	for _, in := range []HostnameInput{{Name: "web1; reboot"}, {Name: "Web1"}, {Name: "web1", Domain: "lab;id"}, {Name: ""}} {
		f := &fakeRunner{}
		res := SetHostname(context.Background(), f, in)
		if res.OK || len(f.ops) != 0 {
			t.Errorf("%+v: no debe ejecutar nada en la VM (ops=%v)", in, f.ops)
		}
	}
}

// TestHostsUpdateScript ejecuta el script real de /etc/hosts con bash sobre
// archivos temporales, en los tres casos posibles.
func TestHostsUpdateScript(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash no disponible")
	}
	cases := []struct{ name, in, want string }{
		{"reemplaza la línea de Debian",
			"127.0.0.1\tlocalhost\n127.0.1.1\tdebian.lan\tdebian\n\n::1 localhost ip6-localhost\n",
			"127.0.0.1\tlocalhost\n127.0.1.1\tweb1.lab.local web1\n\n::1 localhost ip6-localhost\n"},
		{"agrega después de 127.0.0.1 y elimina duplicados",
			"127.0.0.1 localhost\n::1 localhost\n",
			"127.0.0.1 localhost\n127.0.1.1\tweb1.lab.local web1\n::1 localhost\n"},
		{"deja una sola línea 127.0.1.1",
			"127.0.0.1 localhost\n127.0.1.1 a\n127.0.1.1 b\n",
			"127.0.0.1 localhost\n127.0.1.1\tweb1.lab.local web1\n"},
		{"archivo sin 127.0.0.1",
			"10.0.0.5 db\n",
			"10.0.0.5 db\n127.0.1.1\tweb1.lab.local web1\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "hosts")
			os.WriteFile(p, []byte(c.in), 0o644)
			out, err := exec.Command("bash", "-c", "set -eu\n"+hostsUpdateScript(p, "web1.lab.local web1")).CombinedOutput()
			if err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			got, _ := os.ReadFile(p)
			if string(got) != c.want {
				t.Errorf("resultado:\n%q\nquería:\n%q", got, c.want)
			}
			prev, _ := os.ReadFile(p + ".np2-prev")
			if string(prev) != c.in {
				t.Errorf("la copia de respaldo no coincide con el original")
			}
		})
	}
}
