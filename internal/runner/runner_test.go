package runner

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// writeFake crea un ejecutable falso (script de shell) en un directorio
// temporal para probar la clasificación de errores sin ssh ni VirtualBox.
func writeFake(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fake")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestQuote(t *testing.T) {
	cases := map[string]string{
		"vim":        `'vim'`,
		"a b":        `'a b'`,
		"it's":       `'it'\''s'`,
		"$(id)":      `'$(id)'`,
		"`id`; rm":   "'`id`; rm'",
		"":           `''`,
		"a\nb":       "'a\nb'",
		`back\slash`: `'back\slash'`,
	}
	for in, want := range cases {
		if got := Quote(in); got != want {
			t.Errorf("Quote(%q) = %s; quería %s", in, got, want)
		}
	}
}

func TestRemoteCommandHidesScript(t *testing.T) {
	script := "echo 'hola'; $(id) `id` \"x\"\nrm -rf /tmp/x # \\ ;&|<>"
	for _, sudo := range []bool{false, true} {
		cmd := remoteCommand(script, sudo)
		// Fuera del envoltorio fijo, solo debe haber base64: ningún carácter
		// especial del script llega al shell remoto sin codificar.
		re := regexp.MustCompile(`^(sudo -n )?bash -c "\$\(printf %s ([A-Za-z0-9+/=]+) \| base64 -d\)"$`)
		m := re.FindStringSubmatch(cmd)
		if m == nil {
			t.Fatalf("formato inesperado: %s", cmd)
		}
		if (m[1] != "") != sudo {
			t.Errorf("sudo=%v pero comando=%s", sudo, cmd)
		}
		dec, err := base64.StdEncoding.DecodeString(m[2])
		if err != nil || string(dec) != prelude+script {
			t.Errorf("el script decodificado no coincide: %q, %v", dec, err)
		}
	}
}

func TestSSHArgs(t *testing.T) {
	s := &SSH{Host: "192.168.1.68", User: "root", KeyPath: "/k/id", KnownHosts: "/d/kh"}
	a := strings.Join(s.args("CMD"), " ")
	for _, want := range []string{
		"-i /k/id", "-p 22", "BatchMode=yes", "PasswordAuthentication=no",
		"IdentitiesOnly=yes", "StrictHostKeyChecking=accept-new",
		"UserKnownHostsFile=/d/kh", "-- root@192.168.1.68 CMD",
	} {
		if !strings.Contains(a, want) {
			t.Errorf("faltó %q en: %s", want, a)
		}
	}
}

func TestSSHRunClassification(t *testing.T) {
	cases := []struct {
		name string
		body string
		kind Kind
		code int
	}{
		{"éxito", `echo salida; echo aviso >&2`, "", 0},
		{"conexión (255)", `echo "ssh: connect to host x port 22: Connection refused" >&2; exit 255`, KindConnect, 255},
		{"script falla", `echo "boom" >&2; exit 3`, KindExit, 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &SSH{Host: "h", User: "root", KeyPath: "k", Bin: writeFake(t, c.body)}
			res, err := s.Run(context.Background(), "true")
			if c.kind == "" {
				if err != nil || res.Stdout != "salida\n" || res.Stderr != "aviso\n" {
					t.Fatalf("res=%+v err=%v", res, err)
				}
				return
			}
			var re *Error
			if !errors.As(err, &re) || re.Kind != c.kind || res.ExitCode != c.code {
				t.Fatalf("err=%v res=%+v", err, res)
			}
			if Explain(err) == "" {
				t.Error("Explain vacío")
			}
		})
	}
}

func TestSSHRunTimeout(t *testing.T) {
	s := &SSH{Host: "h", User: "root", KeyPath: "k", Bin: writeFake(t, `exec sleep 10`)}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := s.Run(ctx, "true")
	var re *Error
	if !errors.As(err, &re) || re.Kind != KindTimeout {
		t.Fatalf("err=%v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("tardó demasiado: %v", time.Since(start))
	}
}

func TestSSHBinaryMissing(t *testing.T) {
	s := &SSH{Host: "h", User: "root", KeyPath: "k", Bin: "/no/existe/ssh"}
	_, err := s.Run(context.Background(), "true")
	var re *Error
	if !errors.As(err, &re) || re.Kind != KindExec {
		t.Fatalf("err=%v", err)
	}
}

func TestGuestBuildArgs(t *testing.T) {
	root := &Guest{VM: "mv1", User: "root"}
	a := root.BuildArgs("/tmp/pw", "echo hi")
	if strings.Join(a[:3], " ") != "guestcontrol mv1 run" {
		t.Errorf("args: %v", a)
	}
	if strings.Join(a[len(a)-4:len(a)-1], " ") != "env bash -c" {
		t.Errorf("el comando debe ir como env bash -c <script>: %v", a)
	}
	body := a[len(a)-1]
	if strings.Contains(body, "sudo") || !strings.Contains(body, "echo hi") {
		t.Errorf("root no debe usar sudo: %q", body)
	}

	user := &Guest{VM: "mv1", User: "miguel", Password: "p'w d"}
	a = user.BuildArgs("/tmp/pw", "echo hi")
	body = a[len(a)-1]
	if !strings.Contains(body, `sudo -S -p ''`) || !strings.Contains(body, `'p'\''w d'`) {
		t.Errorf("contraseña de sudo mal escapada: %q", body)
	}
	joined := strings.Join(a[:len(a)-1], " ")
	if strings.Contains(joined, "p'w") {
		t.Error("la contraseña no debe aparecer entre las opciones de VBoxManage")
	}
	if !strings.Contains(joined, "--passwordfile /tmp/pw") {
		t.Errorf("falta --passwordfile: %s", joined)
	}

	nopw := &Guest{VM: "mv1", User: "miguel"}
	a = nopw.BuildArgs("/tmp/pw", "x")
	if !strings.Contains(a[len(a)-1], "sudo -n bash -c") {
		t.Errorf("sin contraseña debe usar sudo -n: %q", a[len(a)-1])
	}
}

func TestGuestRunClassification(t *testing.T) {
	g := &Guest{VM: "mv1", User: "root", VBoxManage: writeFake(t, `echo "VBoxManage: error: The guest execution service is not ready" >&2; exit 1`)}
	_, err := g.Run(context.Background(), "true")
	var re *Error
	if !errors.As(err, &re) || re.Kind != KindConnect {
		t.Fatalf("err=%v", err)
	}
	if strings.Contains(re.Result.Command, "secret") {
		t.Error("el comando descrito no debe incluir secretos")
	}
}

func TestJournal(t *testing.T) {
	j, err := NewJournal(filepath.Join(t.TempDir(), "logs", "ops.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	fake := &SSH{Host: "h", User: "root", KeyPath: "k", Bin: writeFake(t, `echo ok`)}
	jr := Journaled{Runner: fake, J: j, Target: "test"}
	for i := 0; i < 3; i++ {
		if _, err := jr.Run(WithOp(context.Background(), "prueba"), "echo "+string(rune('a'+i))); err != nil {
			t.Fatal(err)
		}
	}
	got, err := j.Tail(2)
	if err != nil || len(got) != 2 {
		t.Fatalf("got %d, %v", len(got), err)
	}
	if got[0].Script != "echo c" || got[0].Op != "prueba" || got[0].Target != "test" || got[0].Transport != "ssh" {
		t.Errorf("entrada inesperada: %+v", got[0])
	}
}
