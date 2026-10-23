package ops

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"np2auto/internal/config"
)

// fakeBin crea un ejecutable de shell para simular ssh-keygen o ssh.
func fakeBin(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// fakeKeygen imita ssh-keygen: con -f escribe el par; con -l da una huella.
const fakeKeygen = `
case " $* " in
  *" -l "*) echo "256 SHA256:huellaFalsa np2 (ED25519)"; exit 0 ;;
esac
while [ $# -gt 0 ]; do [ "$1" = "-f" ] && f="$2"; shift; done
echo "PRIVADA" > "$f"
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFalsa np2-prueba" > "$f.pub"
`

func userEnv(t *testing.T, f *fakeRunner, sshBody string) Env {
	return Env{
		Target:  config.Target{ID: "test", Host: "192.0.2.10", Port: 22},
		Runner:  f,
		DataDir: t.TempDir(),
		Keygen:  fakeBin(t, "ssh-keygen", fakeKeygen),
		SSHBin:  fakeBin(t, "ssh", sshBody),
		Now:     func() time.Time { return time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC) },
	}
}

func TestCreateUserWithKeysAndSudo(t *testing.T) {
	f := &fakeRunner{stdout: map[string]string{
		"usuarios/verificar": "uid=1001(ana) gid=1001(ana) groups=1001(ana),27(sudo)\ncontraseña: bloqueada\nsudo: sí\npasswordauthentication no\npubkeyauthentication yes\n",
	}}
	env := userEnv(t, f, `echo "sesión iniciada como ana"; echo "sudo sin contraseña: correcto"`)
	res := CreateUser(context.Background(), env, CreateUserInput{Name: "ana", FullName: "Ana Pérez", Sudo: true, Keys: true, Password: "ignorada123"})
	if !res.OK {
		t.Fatalf("debería terminar bien: %+v", res.Steps)
	}
	want := "usuarios/comprobar,usuarios/crear,usuarios/bloquear,usuarios/sudo,usuarios/autorizar,usuarios/verificar"
	if got := strings.Join(f.ops, ","); got != want {
		t.Errorf("pasos %s; quería %s", got, want)
	}
	all := strings.Join(f.scripts, "\n")
	for _, s := range []string{"useradd -m -U -s /bin/bash -c 'Ana Pérez' -- \"$u\"", "passwd -l -- 'ana'", "NOPASSWD: ALL", "visudo -cf", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFalsa"} {
		if !strings.Contains(all, s) {
			t.Errorf("falta %q en los scripts", s)
		}
	}
	if strings.Contains(all, "ignorada123") || strings.Contains(all, "chpasswd") {
		t.Error("con llaves no se debe asignar contraseña")
	}
	if res.DownloadName != "id_ed25519_ana_test" || filepath.Base(res.KeyPath) != "test_ana_ed25519" {
		t.Errorf("llave: %q %q", res.DownloadName, res.KeyPath)
	}
	if _, err := os.Stat(res.KeyPath); err != nil {
		t.Errorf("la llave privada debe quedar para descargar: %v", err)
	}
	last := res.Steps[len(res.Steps)-1]
	if !strings.Contains(last.Name, "Iniciar sesión por SSH como ana") || !strings.Contains(last.Detail, "sudo sin contraseña: correcto") {
		t.Errorf("última verificación: %+v", last)
	}
	var acct Step
	for _, s := range res.Steps {
		if s.Name == "Verificar la cuenta" {
			acct = s
		}
	}
	if !strings.Contains(acct.Detail, "SSH con contraseña para este usuario: deshabilitado") {
		t.Errorf("verificación de la cuenta: %q", acct.Detail)
	}
}

func TestCreateUserWithPassword(t *testing.T) {
	f := &fakeRunner{stdout: map[string]string{
		"usuarios/verificar": "uid=1002(luis)\ncontraseña: asignada\nsudo: no\n",
	}}
	res := CreateUser(context.Background(), userEnv(t, f, "exit 1"), CreateUserInput{Name: "luis", Password: "Clave'Segura1"})
	if !res.OK {
		t.Fatalf("debería terminar bien: %+v", res.Steps)
	}
	want := "usuarios/comprobar,usuarios/crear,usuarios/contrasena,usuarios/verificar"
	if got := strings.Join(f.ops, ","); got != want {
		t.Errorf("pasos %s; quería %s", got, want)
	}
	if !strings.Contains(f.scripts[2], `'Clave'\''Segura1' | chpasswd`) {
		t.Errorf("contraseña mal escapada: %s", f.scripts[2])
	}
	if res.KeyPath != "" {
		t.Error("sin llaves no debe haber descarga")
	}
}

func TestCreateUserUndoesOnFailure(t *testing.T) {
	f := &fakeRunner{failOn: "usuarios/sudo"}
	res := CreateUser(context.Background(), userEnv(t, f, "exit 1"), CreateUserInput{Name: "ana", Sudo: true, Keys: true})
	if res.OK {
		t.Fatal("no debía terminar bien")
	}
	if f.ops[len(f.ops)-1] != "usuarios/deshacer" || !strings.Contains(f.scripts[len(f.scripts)-1], "userdel -r") {
		t.Errorf("debía deshacer la creación: %v", f.ops)
	}
}

func TestCreateUserLoginFailureKeepsAccount(t *testing.T) {
	f := &fakeRunner{stdout: map[string]string{"usuarios/verificar": "contraseña: bloqueada\n"}}
	res := CreateUser(context.Background(), userEnv(t, f, `echo "Connection refused" >&2; exit 255`), CreateUserInput{Name: "ana", Keys: true})
	if res.OK {
		t.Fatal("no debía terminar bien")
	}
	for _, op := range f.ops {
		if op == "usuarios/deshacer" {
			t.Error("si solo falla la conexión de prueba, no se debe borrar la cuenta")
		}
	}
	if d := res.Steps[len(res.Steps)-1].Detail; !strings.Contains(d, "La cuenta quedó creada") {
		t.Errorf("detalle: %q", d)
	}
}

func TestCreateUserValidation(t *testing.T) {
	for _, in := range []CreateUserInput{
		{Name: "root", Keys: true},
		{Name: "Ana", Keys: true},
		{Name: "ana;id", Keys: true},
		{Name: "ana"},                                 // sin contraseña ni llaves
		{Name: "ana", Password: "corta"},              // contraseña corta
		{Name: "ana", Keys: true, FullName: "a:b"},    // GECOS inválido
		{Name: "haproxy", Password: "suficiente1234"}, // cuenta del sistema
	} {
		f := &fakeRunner{}
		if res := CreateUser(context.Background(), userEnv(t, f, "exit 1"), in); res.OK || len(f.ops) != 0 {
			t.Errorf("%+v: no debe ejecutar nada en la VM", in)
		}
	}
}

func TestDeleteUser(t *testing.T) {
	f := &fakeRunner{stdout: map[string]string{
		"usuarios/consultar": "home=/home/ana\nuid=1001(ana)\ndirectorio personal: /home/ana (24K)\nprocesos en ejecución: 0\n",
		"usuarios/verificar": "el usuario ana ya no existe\narchivos: /home/ana eliminado\n",
	}}
	res := DeleteUser(context.Background(), f, DeleteUserInput{Name: "ana", RemoveFiles: true}, "root", "miguel")
	if !res.OK {
		t.Fatalf("debería terminar bien: %+v", res.Steps)
	}
	if !strings.Contains(f.scripts[1], `userdel -r -- "$u"`) || !strings.Contains(f.scripts[1], "/etc/sudoers.d/np2-ana") {
		t.Errorf("script de eliminación: %s", f.scripts[1])
	}
	if !strings.Contains(f.scripts[2], `h='/home/ana'`) {
		t.Errorf("la verificación debe revisar el directorio personal: %s", f.scripts[2])
	}
	if d := res.Steps[0].Detail; strings.Contains(d, "home=") || !strings.Contains(d, "/home/ana (24K)") {
		t.Errorf("estado anterior: %q", d)
	}
}

func TestDeleteUserKeepsFiles(t *testing.T) {
	f := &fakeRunner{stdout: map[string]string{
		"usuarios/consultar": "home=/home/ana\n",
		"usuarios/verificar": "el usuario ana ya no existe\narchivos: /home/ana se conserva\n",
	}}
	res := DeleteUser(context.Background(), f, DeleteUserInput{Name: "ana"})
	if !res.OK || strings.Contains(f.scripts[1], "userdel -r") {
		t.Fatalf("sin la casilla no debe usar -r: ok=%v %s", res.OK, f.scripts[1])
	}
	// Con la casilla marcada, si el directorio sigue ahí es un fallo.
	f.ops, f.scripts = nil, nil
	if res := DeleteUser(context.Background(), f, DeleteUserInput{Name: "ana", RemoveFiles: true}); res.OK {
		t.Error("debía informar que el directorio no se borró")
	}
}

func TestDeleteUserProtected(t *testing.T) {
	for _, name := range []string{"root", "sshd", "miguel", "Ana", "a b"} {
		f := &fakeRunner{}
		if res := DeleteUser(context.Background(), f, DeleteUserInput{Name: name}, "root", "miguel"); res.OK || len(f.ops) != 0 {
			t.Errorf("%q: no debe ejecutar nada en la VM", name)
		}
	}
}

// TestListUsersScript ejecuta el listado real (solo lectura) en este equipo.
func TestListUsersScript(t *testing.T) {
	for _, bin := range []string{"bash", "getent", "passwd"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skip(bin + " no disponible")
		}
	}
	res := ListUsers(context.Background(), localRunner{})
	if !res.OK || !strings.HasPrefix(res.Preview, "USUARIO") {
		t.Fatalf("listado: %+v\n%s", res.Steps, res.Preview)
	}
	t.Logf("\n%s", res.Preview)
}
