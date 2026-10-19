//go:build integration

package ops

// Prueba de integración contra un sshd REAL. No corre con "go test ./..."; se
// activa con la etiqueta "integration" y estas variables de entorno:
//
//	NP2_IT_PORT  puerto del sshd de prueba (p. ej. 2222), escuchando en 127.0.0.1
//	NP2_IT_KEY   llave privada con la que se puede entrar como root (arranque)
//
// Requisitos del entorno de prueba (descritos en el README):
//   - sshd de prueba ejecutándose como root con la configuración por defecto
//     (que incluye /etc/ssh/sshd_config.d/*.conf).
//   - un "systemctl" en el PATH que, para "reload ssh", recargue ese sshd
//     (la prueba no usa systemd real).
//
// La prueba modifica /etc/ssh/sshd_config.d/ del equipo donde corre: úsela
// solo en un entorno desechable.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"np2auto/internal/config"
	"np2auto/internal/runner"
)

func TestConfigureRootKeyIntegration(t *testing.T) {
	port, key := os.Getenv("NP2_IT_PORT"), os.Getenv("NP2_IT_KEY")
	if port == "" || key == "" {
		t.Skip("defina NP2_IT_PORT y NP2_IT_KEY")
	}
	var portNum int
	for _, c := range port {
		portNum = portNum*10 + int(c-'0')
	}
	dir := t.TempDir()
	kh := filepath.Join(dir, "known_hosts")
	target := config.Target{ID: "it", Host: "127.0.0.1", Port: portNum, User: "root", KeyPath: key}
	boot := &runner.SSH{Host: target.Host, Port: portNum, User: "root", KeyPath: key, KnownHosts: kh}

	var switched string
	env := Env{
		Target: target, Runner: boot, DataDir: dir, KnownHosts: kh,
		OnSuccess: func(p string) error { switched = p; return nil },
	}
	t.Cleanup(func() { os.Remove(dropIn); os.Remove(dropIn + ".prev") })
	os.Remove(dropIn)

	// Precondición: el sshd de prueba permite contraseña; si no, la comprobación
	// final no demostraría nada.
	if out := passwordProbe(port); !strings.Contains(out, "password") {
		t.Skipf("el sshd de prueba ya rechaza contraseñas; no se puede demostrar el cambio: %s", out)
	}

	res := ConfigureRootKey(context.Background(), env)
	for _, s := range res.Steps {
		t.Logf("[%v] %s — %s", s.OK, s.Name, s.Detail)
	}
	if !res.OK || !res.Hardened || res.RolledBack {
		t.Fatalf("la operación debía completarse: %+v", res)
	}
	if switched != res.KeyPath || res.Fingerprint == "" || res.DownloadName != "id_ed25519_root_it" {
		t.Errorf("resultado incompleto: switched=%q %+v", switched, res)
	}
	if st, err := os.Stat(res.KeyPath); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("la llave privada debe existir con permisos 0600: %v %v", st, err)
	}

	// El archivo de endurecimiento existe y el efectivo de sshd lo refleja.
	out, err := exec.Command("sshd", "-T").Output()
	if err != nil || !strings.Contains(string(out), "passwordauthentication no") {
		t.Errorf("sshd -T debería mostrar passwordauthentication no: %v\n%s", err, out)
	}

	// La llave nueva entra; la contraseña ya no es una opción.
	nuevo := &runner.SSH{Host: target.Host, Port: portNum, User: "root", KeyPath: res.KeyPath, KnownHosts: kh}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if r, err := nuevo.Run(ctx, "id -un"); err != nil || strings.TrimSpace(r.Stdout) != "root" {
		t.Errorf("la llave nueva debería entrar como root: %v %+v", err, r)
	}
	// El daemon realmente recargó: ya solo ofrece "publickey" (antes ofrecía "password").
	if out := passwordProbe(port); !strings.Contains(out, "Permission denied (publickey).") || strings.Contains(out, "password") {
		t.Errorf("tras endurecer solo debería ofrecerse publickey; respuesta: %s", out)
	}

	// Segunda ejecución: genera otra llave, conserva la anterior como respaldo y sigue funcionando.
	env.Runner = nuevo
	res2 := ConfigureRootKey(context.Background(), env)
	if !res2.OK {
		t.Fatalf("la segunda ejecución debía funcionar: %+v", res2.Steps)
	}
	matches, _ := filepath.Glob(res.KeyPath + ".old-*")
	if len(matches) == 0 {
		t.Error("debería conservarse la llave anterior como respaldo (.old-*)")
	}
}

// Si la llave nueva no permite entrar, el módulo debe detenerse ANTES de
// endurecer, no dejar la configuración de SSH modificada y retirar la llave.
func TestConfigureRootKeyStopsBeforeHardening(t *testing.T) {
	port, key := os.Getenv("NP2_IT_PORT"), os.Getenv("NP2_IT_KEY")
	if port == "" || key == "" {
		t.Skip("defina NP2_IT_PORT y NP2_IT_KEY")
	}
	var portNum int
	for _, c := range port {
		portNum = portNum*10 + int(c-'0')
	}
	dir := t.TempDir()
	kh := filepath.Join(dir, "known_hosts")

	// ssh-keygen "defectuoso": genera la llave, pero entrega una pública que
	// NO corresponde a la privada. La llave se autoriza, pero no puede entrar.
	fake := filepath.Join(dir, "fake-keygen")
	script := `#!/bin/sh
if [ "$1" = "-l" ]; then exec ssh-keygen "$@"; fi
for last; do :; done
ssh-keygen "$@"
ssh-keygen -q -t ed25519 -N '' -C otra -f "$last.otra"
cp "$last.otra.pub" "$last.pub"
`
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(dropIn); os.Remove(dropIn + ".prev") })
	os.Remove(dropIn)

	target := config.Target{ID: "it2", Host: "127.0.0.1", Port: portNum, User: "root", KeyPath: key}
	boot := &runner.SSH{Host: target.Host, Port: portNum, User: "root", KeyPath: key, KnownHosts: kh}
	called := false
	res := ConfigureRootKey(context.Background(), Env{
		Target: target, Runner: boot, DataDir: dir, KnownHosts: kh, Keygen: fake,
		OnSuccess: func(string) error { called = true; return nil },
	})
	for _, s := range res.Steps {
		t.Logf("[%v] %s — %s", s.OK, s.Name, s.Detail)
	}
	if res.OK || res.Hardened || called {
		t.Fatalf("debía fallar sin endurecer ni cambiar de canal: %+v", res)
	}
	if _, err := os.Stat(dropIn); err == nil {
		t.Error("no debe existir el archivo de endurecimiento")
	}
	last := res.Steps[len(res.Steps)-1]
	if !last.OK || !strings.Contains(last.Name, "limpieza") {
		t.Errorf("el último paso debe ser la limpieza exitosa: %+v", last)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "keys", "it2_root_ed25519*")); len(left) != 0 {
		// Quedan los archivos auxiliares del keygen falso (.otra*), no la llave provisional.
		for _, f := range left {
			if !strings.Contains(f, ".otra") {
				t.Errorf("quedó un archivo de llave sin limpiar: %s", f)
			}
		}
	}
	// La contraseña NO se deshabilitó (el sshd de prueba la permite por defecto).
	out, err := exec.Command("sshd", "-T").Output()
	if err != nil || strings.Contains(string(out), "passwordauthentication no") {
		t.Errorf("sshd -T no debería mostrar passwordauthentication no tras un fallo previo al endurecimiento:\n%s", out)
	}
}

// passwordProbe intenta entrar con contraseña (sin ofrecer llaves) y devuelve el
// mensaje del servidor, que lista los métodos de autenticación que acepta.
func passwordProbe(port string) string {
	out, _ := exec.Command("ssh", "-p", port, "-o", "BatchMode=yes", "-o", "PubkeyAuthentication=no",
		"-o", "PreferredAuthentications=password,keyboard-interactive", "-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "root@127.0.0.1", "true").CombinedOutput()
	return string(out)
}
