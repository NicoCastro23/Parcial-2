// Package ops contiene las operaciones de automatización sobre una VM. Cada
// operación recibe un runner.Runner, de modo que funciona igual por Guest
// Additions o por SSH, y devuelve una lista de pasos con su evidencia.
package ops

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"np2auto/internal/config"
	"np2auto/internal/runner"
)

// Step es un paso de una operación, con lo que debe ver el usuario
// (Detail) y la evidencia técnica para el diagnóstico (Technical).
type Step struct {
	Name      string
	OK        bool
	Detail    string
	Technical string
}

// RootKeyResult es el resultado de ConfigureRootKey.
type RootKeyResult struct {
	Steps        []Step
	OK           bool
	Hardened     bool   // true si el login por contraseña quedó deshabilitado
	RolledBack   bool   // true si se revirtió el endurecimiento por una verificación fallida
	Fingerprint  string // huella de la llave pública
	KeyPath      string // llave privada que conserva la aplicación
	DownloadName string // nombre sugerido al descargar la llave privada
}

// Env agrupa las dependencias de ConfigureRootKey.
type Env struct {
	Target     config.Target
	Runner     runner.Runner // canal actual (Guest Additions o SSH)
	DataDir    string
	KnownHosts string
	Keygen     string // por defecto "ssh-keygen"
	SSHBin     string // por defecto "ssh"

	// OnSuccess se invoca al terminar bien para que la aplicación cambie al
	// transporte SSH con la nueva llave.
	OnSuccess func(keyPath string) error
	Now       func() time.Time
}

const dropIn = "/etc/ssh/sshd_config.d/00-np2-hardening.conf"

var rePubKey = regexp.MustCompile(`^ssh-ed25519 [A-Za-z0-9+/=]+( [A-Za-z0-9@_.\-]+)?$`)

// ConfigureRootKey implementa el punto 3.1.2 del enunciado: crear las llaves
// SSH de root, autorizar la pública, asegurar que no haya acceso por login y
// contraseña, y dejar la privada disponible para descargar.
//
// Es segura frente a bloqueos: antes de deshabilitar la contraseña comprueba
// que la llave nueva funciona, y si alguna verificación posterior falla,
// revierte el cambio.
func ConfigureRootKey(ctx context.Context, env Env) *RootKeyResult {
	if env.Keygen == "" {
		env.Keygen = "ssh-keygen"
	}
	if env.Now == nil {
		env.Now = time.Now
	}
	res := &RootKeyResult{}
	ctx = runner.WithOp(ctx, "rootkey")

	// step ejecuta un paso, lo registra y devuelve si salió bien.
	step := func(name string, fn func() (detail, technical string, err error)) bool {
		d, tech, err := fn()
		s := Step{Name: name, OK: err == nil, Detail: d, Technical: tech}
		if err != nil {
			s.Detail = runner.Explain(err)
			var re *runner.Error
			if errors.As(err, &re) {
				s.Technical = joinTech(re.Result)
			} else if tech == "" {
				s.Technical = err.Error()
			}
		}
		res.Steps = append(res.Steps, s)
		return err == nil
	}
	remote := func(op, script string, timeout time.Duration) (runner.Result, error) {
		c, cancel := context.WithTimeout(runner.WithOp(ctx, "rootkey/"+op), timeout)
		defer cancel()
		return env.Runner.Run(c, script)
	}

	// 1. Privilegios y datos básicos de la VM.
	if !step("Comprobar comunicación y privilegios de root en la VM", func() (string, string, error) {
		r, err := remote("comprobar", `
test "$(id -u)" -eq 0 || { echo "el script no se ejecuta como root" >&2; exit 1; }
echo "host: $(hostname)"
. /etc/os-release && echo "sistema: $PRETTY_NAME"
`, 2*time.Minute)
		return firstLines(r.Stdout, 2), joinTech(r), err
	}) {
		return res
	}

	// 2. Servidor SSH instalado y activo.
	if !step("Asegurar que el servidor SSH esté instalado y activo", func() (string, string, error) {
		r, err := remote("instalar-ssh", `
if ! dpkg -s openssh-server >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y -qq openssh-server
  echo "openssh-server instalado"
else
  echo "openssh-server ya estaba instalado"
fi
systemctl enable --now ssh
`, 10*time.Minute)
		return firstLines(r.Stdout, 1), joinTech(r), err
	}) {
		return res
	}

	// 3. Par de llaves (se genera localmente; la privada nunca viaja a la VM).
	// Se crea en una ruta PROVISIONAL: la llave actual de la aplicación puede
	// estar en uso (es la que abre la conexión SSH) y no debe moverse hasta que
	// todo haya salido bien.
	stamp := env.Now().Format("20060102-150405")
	finalKey := filepath.Join(env.DataDir, "keys", env.Target.ID+"_root_ed25519")
	newKey := finalKey + ".new-" + stamp
	var pub string
	if !step("Generar el par de llaves ed25519 (sin frase de seguridad)", func() (string, string, error) {
		if _, err := exec.LookPath(env.Keygen); err != nil {
			return "", "", &runner.Error{Kind: runner.KindExec, Err: fmt.Errorf("no se encontró %s en el equipo donde corre la aplicación", env.Keygen)}
		}
		if err := os.MkdirAll(filepath.Dir(newKey), 0o700); err != nil {
			return "", "", err
		}
		comment := fmt.Sprintf("np2-root@%s-%s", env.Target.ID, env.Now().Format("20060102"))
		out, err := exec.CommandContext(ctx, env.Keygen, "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", newKey).CombinedOutput()
		if err != nil {
			return "", string(out), fmt.Errorf("ssh-keygen falló: %w", err)
		}
		b, err := os.ReadFile(newKey + ".pub")
		if err != nil {
			return "", "", err
		}
		pub = strings.TrimSpace(string(b))
		if !rePubKey.MatchString(pub) {
			return "", "", errors.New("la llave pública generada tiene un formato inesperado")
		}
		fp, _ := exec.CommandContext(ctx, env.Keygen, "-l", "-f", newKey+".pub").Output()
		res.Fingerprint = strings.TrimSpace(string(fp))
		return "Huella: " + res.Fingerprint, "", nil
	}) {
		return res
	}

	// 4. Autorizar la llave pública para root (idempotente).
	if !step("Autorizar la llave pública en /root/.ssh/authorized_keys", func() (string, string, error) {
		r, err := remote("autorizar-llave", `
install -d -m 700 /root/.ssh
touch /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
key=`+runner.Quote(pub)+`
if grep -qxF -- "$key" /root/.ssh/authorized_keys; then
  echo "la llave ya estaba autorizada"
else
  printf '%s\n' "$key" >> /root/.ssh/authorized_keys
  echo "llave agregada"
fi
`, 2*time.Minute)
		return firstLines(r.Stdout, 1), joinTech(r), err
	}) {
		return res
	}

	// cleanup retira la llave nueva (de la VM y del equipo) cuando la operación
	// no se completó, para no dejar credenciales sueltas en root.
	cleanup := func() {
		step("Retirar la llave nueva (limpieza)", func() (string, string, error) {
			r, err := remote("limpieza", `
f=/root/.ssh/authorized_keys
key=`+runner.Quote(pub)+`
tmp=$(mktemp)
grep -vxF -- "$key" "$f" > "$tmp" || true
cat "$tmp" > "$f"
rm -f "$tmp"
`, time.Minute)
			if err == nil {
				os.Remove(newKey)
				os.Remove(newKey + ".pub")
			}
			return "La llave nueva se retiró de la VM y del equipo", joinTech(r), err
		})
	}

	keyRunner := &runner.SSH{
		Host: env.Target.Host, Port: env.Target.Port, User: "root",
		KeyPath: newKey, KnownHosts: env.KnownHosts, Bin: env.SSHBin,
	}
	verify := func(op string) (string, string, error) {
		c, cancel := context.WithTimeout(runner.WithOp(ctx, "rootkey/"+op), time.Minute)
		defer cancel()
		r, err := keyRunner.Run(c, `echo acceso-con-llave-ok`)
		if err == nil && !strings.Contains(r.Stdout, "acceso-con-llave-ok") {
			err = &runner.Error{Kind: runner.KindExit, Result: r, Err: errors.New("respuesta inesperada")}
		}
		return "Inicio de sesión como root con la llave nueva: correcto", joinTech(r), err
	}

	// 5. Probar la llave ANTES de endurecer: si no funciona, no se toca nada.
	if !step("Verificar el acceso por SSH con la llave nueva (antes de endurecer)", func() (string, string, error) {
		return verify("verificar-previo")
	}) {
		res.Steps[len(res.Steps)-1].Detail += " No se modificó la configuración de SSH: el acceso por contraseña sigue como estaba."
		cleanup()
		return res
	}

	rollback := func() bool {
		r, err := remote("revertir", `
f=`+dropIn+`
if [ -f "$f.prev" ]; then mv "$f.prev" "$f"; else rm -f "$f"; fi
(systemctl reload ssh 2>/dev/null || systemctl reload sshd)
`, 2*time.Minute)
		res.RolledBack = true
		detail := "Se revirtió el endurecimiento de SSH para evitar un bloqueo."
		if err != nil {
			detail = "No se pudo revertir automáticamente el endurecimiento: " + runner.Explain(err)
		}
		res.Steps = append(res.Steps, Step{Name: "Revertir el endurecimiento de SSH", OK: err == nil, Detail: detail, Technical: joinTech(r)})
		return err == nil
	}

	// 6. Deshabilitar login con contraseña (archivo propio en sshd_config.d).
	if !step("Deshabilitar el acceso por contraseña (solo llave pública)", func() (string, string, error) {
		r, err := remote("endurecer", `
f=`+dropIn+`
install -d -m 755 "$(dirname "$f")"
if [ -f "$f" ]; then cp -p "$f" "$f.prev"; fi
cat > "$f" <<'NP2EOF'
# Gestionado por la aplicación de automatización NP2.
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
NP2EOF
chmod 644 "$f"
if ! sshd -t; then
  rm -f "$f"
  if [ -f "$f.prev" ]; then mv "$f.prev" "$f"; fi
  echo "sshd -t rechazó la configuración; se restauró el estado anterior" >&2
  exit 1
fi
(systemctl reload ssh 2>/dev/null || systemctl reload sshd)
echo "configuración aplicada en $f"
`, 2*time.Minute)
		return firstLines(r.Stdout, 1), joinTech(r), err
	}) {
		cleanup() // sshd -t rechazó el cambio y el propio script ya restauró el estado
		return res
	}

	// 7. Configuración efectiva (lo que sshd realmente aplica).
	if !step("Comprobar la configuración efectiva de sshd", func() (string, string, error) {
		r, err := remote("config-efectiva", `sshd -T | grep -E '^(passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|permitrootlogin) '`, time.Minute)
		if err != nil {
			return "", joinTech(r), err
		}
		eff := parseEffective(r.Stdout)
		problems := []string{}
		if eff["passwordauthentication"] != "no" {
			problems = append(problems, "passwordauthentication="+eff["passwordauthentication"])
		}
		if eff["pubkeyauthentication"] != "yes" {
			problems = append(problems, "pubkeyauthentication="+eff["pubkeyauthentication"])
		}
		if v := eff["permitrootlogin"]; v != "prohibit-password" && v != "without-password" {
			problems = append(problems, "permitrootlogin="+v)
		}
		if len(problems) > 0 {
			return "", joinTech(r), &runner.Error{Kind: runner.KindExit, Result: r, Err: fmt.Errorf("valores inesperados: %s", strings.Join(problems, ", "))}
		}
		return "passwordauthentication=no, pubkeyauthentication=yes, permitrootlogin=" + eff["permitrootlogin"], joinTech(r), nil
	}) {
		if rollback() {
			cleanup()
		}
		return res
	}
	res.Hardened = true

	// 8. Volver a probar la llave con la configuración ya endurecida.
	if !step("Verificar el acceso por SSH con llave (después de endurecer)", func() (string, string, error) {
		return verify("verificar-posterior")
	}) {
		res.Hardened = false
		if rollback() {
			cleanup()
		}
		return res
	}

	// 9. Promover la llave nueva a llave de la aplicación. Recién ahora se
	// reemplaza la anterior (queda como respaldo local) y se cambia el canal.
	if !step("Cambiar el canal de la aplicación a SSH con llave", func() (string, string, error) {
		r, _ := remote("limpiar", `rm -f `+dropIn+`.prev`, time.Minute)
		for _, ext := range []string{"", ".pub"} {
			if _, err := os.Stat(finalKey + ext); err == nil {
				if err := os.Rename(finalKey+ext, finalKey+ext+".old-"+stamp); err != nil {
					return "", "", err
				}
			}
			if err := os.Rename(newKey+ext, finalKey+ext); err != nil {
				return "", "", err
			}
		}
		res.KeyPath = finalKey
		if env.OnSuccess != nil {
			if err := env.OnSuccess(finalKey); err != nil {
				return "", "", err
			}
		}
		return "A partir de ahora la VM se administra solo por SSH con llaves", joinTech(r), nil
	}) {
		return res
	}

	res.OK = true
	res.DownloadName = "id_ed25519_root_" + env.Target.ID
	return res
}

func parseEffective(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 {
			m[strings.ToLower(f[0])] = strings.ToLower(f[1])
		}
	}
	return m
}

func firstLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, " · ")
}

func joinTech(r runner.Result) string {
	var b strings.Builder
	if r.Command != "" {
		b.WriteString("$ " + r.Command + "\n")
	}
	if r.Stdout != "" {
		b.WriteString(strings.TrimRight(r.Stdout, "\n") + "\n")
	}
	if r.Stderr != "" {
		b.WriteString("[stderr] " + strings.TrimRight(r.Stderr, "\n") + "\n")
	}
	fmt.Fprintf(&b, "[código de salida %d, %d ms]", r.ExitCode, r.Duration.Milliseconds())
	return b.String()
}
