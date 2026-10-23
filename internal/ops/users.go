package ops

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"np2auto/internal/runner"
	"np2auto/internal/validate"
)

// CreateUserInput son los datos del formulario del punto 3.2.1.
type CreateUserInput struct {
	Name     string
	FullName string // opcional (campo GECOS)
	Sudo     bool   // agregar al grupo sudo
	Keys     bool   // generar llaves; la contraseña queda bloqueada
	Password string // obligatoria si no se generan llaves; se ignora si Keys
}

// Validate comprueba los datos antes de tocar la VM.
func (in CreateUserInput) Validate() error {
	if err := validate.Username(in.Name); err != nil {
		return err
	}
	if validate.ReservedUser(in.Name) {
		return fmt.Errorf("%q es una cuenta del sistema: elija otro nombre", in.Name)
	}
	if _, err := validate.FullName(in.FullName); err != nil {
		return err
	}
	if !in.Keys {
		if in.Password == "" {
			return errors.New("indique una contraseña o marque «Generar llaves»: sin ninguna de las dos el usuario no podría iniciar sesión")
		}
		if err := validate.Password(in.Password); err != nil {
			return err
		}
	}
	return nil
}

// UserResult es el resultado de CreateUser; incluye la llave para descargar.
type UserResult struct {
	Result
	KeyPath      string
	DownloadName string
	Fingerprint  string
}

func sudoersFile(user string) string { return "/etc/sudoers.d/np2-" + user }

// CreateUser implementa el punto 3.2.1: crea el usuario, opcionalmente con
// privilegios de sudo y con un par de llaves. Con llaves, la contraseña del
// usuario queda bloqueada: solo puede entrar con la llave (ni por SSH ni en
// la consola con contraseña) y sudo no le pide contraseña.
func CreateUser(ctx context.Context, env Env, in CreateUserInput) *UserResult {
	out := &UserResult{}
	if env.Keygen == "" {
		env.Keygen = "ssh-keygen"
	}
	if env.Now == nil {
		env.Now = time.Now
	}
	if in.Keys {
		in.Password = ""
	}
	o := newRun(runner.WithSecret(ctx, in.Password), env.Runner, "usuarios")
	o.res = &out.Result
	if err := in.Validate(); err != nil {
		o.res.Steps = append(o.res.Steps, Step{Name: "Validar los datos", Detail: err.Error()})
		return out
	}
	in.FullName, _ = validate.FullName(in.FullName) // ya validado: solo recorta espacios
	u := runner.Quote(in.Name)

	// 1. Que no exista.
	if !o.step("Comprobar que el usuario "+in.Name+" no exista", func() (string, string, error) {
		r, err := o.remote("comprobar", `
u=`+u+`
if id -u "$u" >/dev/null 2>&1; then echo "el usuario $u ya existe: $(id "$u")" >&2; exit 1; fi
echo "el usuario $u no existe: se puede crear"
`, time.Minute)
		return firstLines(r.Stdout, 1), joinTech(r), err
	}) {
		return out
	}

	// 2. Creación (con directorio personal y grupo propio).
	if !o.step("Crear el usuario con su directorio personal", func() (string, string, error) {
		comment := ""
		if in.FullName != "" {
			comment = " -c " + runner.Quote(in.FullName)
		}
		r, err := o.remote("crear", `
u=`+u+`
useradd -m -U -s /bin/bash`+comment+` -- "$u"
echo "creado: $(id "$u")"
echo "directorio personal: $(getent passwd "$u" | cut -d: -f6)"
`, time.Minute)
		return firstLines(r.Stdout, 2), joinTech(r), err
	}) {
		return out
	}

	// Si algo falla de aquí en adelante se deshace todo: un usuario a medio
	// configurar (p. ej. con sudo pero sin llave) es peor que ninguno.
	undo := func() {
		o.step("Deshacer: eliminar el usuario a medio crear", func() (string, string, error) {
			r, err := o.remote("deshacer", `
u=`+u+`
rm -f `+runner.Quote(sudoersFile(in.Name))+`
pkill -KILL -u "$u" 2>/dev/null || true
userdel -r "$u" 2>/dev/null || userdel "$u"
echo "se eliminó $u"
`, time.Minute)
			return "Se eliminó el usuario para no dejarlo a medio configurar", joinTech(r), err
		})
	}

	// 3. Contraseña: bloqueada con llaves; si no, la indicada.
	if in.Keys {
		if !o.step("Bloquear la contraseña (solo acceso con llave)", func() (string, string, error) {
			r, err := o.remote("bloquear", `passwd -l -- `+u+`
passwd -S -- `+u, time.Minute)
			return "Sin contraseña válida: el usuario no puede entrar con login y contraseña (ni por SSH ni en consola)", joinTech(r), err
		}) {
			undo()
			return out
		}
	} else {
		if !o.step("Asignar la contraseña", func() (string, string, error) {
			r, err := o.remote("contrasena", `printf '%s:%s\n' `+u+` `+runner.Quote(in.Password)+` | chpasswd
echo "contraseña asignada"`, time.Minute)
			return "Contraseña asignada (no se guarda en el registro)", joinTech(r), err
		}) {
			undo()
			return out
		}
	}

	// 4. sudo.
	if in.Sudo {
		if !o.step("Otorgar privilegios de sudo", func() (string, string, error) {
			script := `
u=` + u + `
if ! command -v sudo >/dev/null 2>&1; then
  apt-get update -q -o DPkg::Lock::Timeout=180
  apt-get install -y -q ` + aptOpts + ` sudo
  echo "se instaló el paquete sudo"
fi
usermod -aG sudo -- "$u"
echo "agregado al grupo sudo"
`
			if in.Keys {
				// Sin contraseña, sudo no tendría con qué autenticarlo.
				script += `
f=` + runner.Quote(sudoersFile(in.Name)) + `
tmp=$(mktemp)
printf '%s ALL=(ALL:ALL) NOPASSWD: ALL\n' "$u" > "$tmp"
visudo -cf "$tmp" >/dev/null
install -m 440 -o root -g root "$tmp" "$f"
rm -f "$tmp"
echo "sudo sin contraseña en $f (el usuario solo entra con su llave)"
`
			}
			r, err := o.remote("sudo", script, 10*time.Minute)
			return firstLines(r.Stdout, 2), joinTech(r), err
		}) {
			undo()
			return out
		}
	}

	// 5. Llaves.
	if in.Keys {
		stamp := env.Now().Format("20060102-150405")
		keyPath := filepath.Join(env.DataDir, "keys", env.Target.ID+"_"+in.Name+"_ed25519")
		var pub string
		if !o.step("Generar el par de llaves ed25519", func() (string, string, error) {
			// Si quedó una llave de un usuario anterior con el mismo nombre, se
			// conserva como respaldo.
			for _, ext := range []string{"", ".pub"} {
				if _, err := os.Stat(keyPath + ext); err == nil {
					if err := os.Rename(keyPath+ext, keyPath+ext+".old-"+stamp); err != nil {
						return "", "", err
					}
				}
			}
			p, fp, err := generateKey(ctx, env.Keygen, keyPath, fmt.Sprintf("np2-%s@%s-%s", in.Name, env.Target.ID, env.Now().Format("20060102")))
			if err != nil {
				return "", "", err
			}
			pub, out.Fingerprint = p, fp
			return "Huella: " + fp, "", nil
		}) {
			undo()
			return out
		}
		if !o.step("Instalar la llave pública en ~"+in.Name+"/.ssh/authorized_keys", func() (string, string, error) {
			r, err := o.remote("autorizar", `
u=`+u+`
h=$(getent passwd "$u" | cut -d: -f6)
install -d -m 700 -o "$u" -g "$u" "$h/.ssh"
printf '%s\n' `+runner.Quote(pub)+` > "$h/.ssh/authorized_keys"
chown "$u:$u" "$h/.ssh/authorized_keys"
chmod 600 "$h/.ssh/authorized_keys"
echo "llave instalada en $h/.ssh/authorized_keys"
`, time.Minute)
			return firstLines(r.Stdout, 1), joinTech(r), err
		}) {
			os.Remove(keyPath)
			os.Remove(keyPath + ".pub")
			undo()
			return out
		}
		out.KeyPath = keyPath
		out.DownloadName = "id_ed25519_" + in.Name + "_" + env.Target.ID
	}

	// 6. Verificación en la VM.
	if !o.step("Verificar la cuenta", func() (string, string, error) {
		r, err := o.remote("verificar", `
u=`+u+`
id "$u"
case "$(passwd -S -- "$u" | awk '{print $2}')" in
  L) echo "contraseña: bloqueada" ;;
  P) echo "contraseña: asignada" ;;
  *) echo "contraseña: sin asignar" ;;
esac
if id -nG "$u" | tr ' ' '\n' | grep -qx sudo; then echo "sudo: sí"; else echo "sudo: no"; fi
if command -v sshd >/dev/null 2>&1; then
  sshd -T -C user="$u",host=localhost,addr=127.0.0.1 2>/dev/null | grep -E '^(passwordauthentication|pubkeyauthentication) ' || true
fi
`, time.Minute)
		if err != nil {
			return "", joinTech(r), err
		}
		eff := parseEffective(r.Stdout)
		var problems []string
		if in.Sudo && !strings.Contains(r.Stdout, "sudo: sí") {
			problems = append(problems, "no quedó en el grupo sudo")
		}
		if in.Keys && !strings.Contains(r.Stdout, "contraseña: bloqueada") {
			problems = append(problems, "la contraseña no quedó bloqueada")
		}
		if !in.Keys && !strings.Contains(r.Stdout, "contraseña: asignada") {
			problems = append(problems, "la contraseña no quedó asignada")
		}
		if len(problems) > 0 {
			return "", joinTech(r), errors.New("La cuenta no quedó como se pidió: " + strings.Join(problems, "; "))
		}
		d := firstLines(r.Stdout, 3)
		if v := eff["passwordauthentication"]; v != "" {
			d += " · SSH con contraseña para este usuario: " + map[string]string{"no": "deshabilitado", "yes": "habilitado"}[v]
		}
		return d, joinTech(r), nil
	}) {
		return out
	}

	// 7. Con llaves: iniciar sesión como el usuario nuevo, como lo haría él.
	if in.Keys {
		ur := &runner.SSH{
			Host: env.Target.Host, Port: env.Target.Port, User: in.Name, NoSudo: true,
			KeyPath: out.KeyPath, KnownHosts: env.KnownHosts, Bin: env.SSHBin,
		}
		if !o.step("Iniciar sesión por SSH como "+in.Name+" con la llave nueva", func() (string, string, error) {
			script := `echo "sesión iniciada como $(id -un)"`
			if in.Sudo {
				script += `
sudo -n true && echo "sudo sin contraseña: correcto"`
			}
			c, cancel := context.WithTimeout(runner.WithOp(o.ctx, "usuarios/probar-llave"), time.Minute)
			defer cancel()
			r, err := ur.Run(c, script)
			if err == nil && !strings.Contains(r.Stdout, "sesión iniciada como "+in.Name) {
				err = errors.New("respuesta inesperada al iniciar sesión")
			}
			return firstLines(r.Stdout, 2), joinTech(r), err
		}) {
			// El usuario quedó bien creado; lo que falló es la conexión desde
			// este equipo. Se informa sin deshacer.
			o.res.Steps[len(o.res.Steps)-1].Detail += " La cuenta quedó creada; revise que el servidor SSH de la VM esté activo y sea accesible desde este equipo."
			return out
		}
	}
	o.done()
	return out
}

// generateKey crea un par ed25519 sin frase de seguridad en path y devuelve la
// llave pública y su huella.
func generateKey(ctx context.Context, keygen, path, comment string) (pub, fingerprint string, err error) {
	if _, err := exec.LookPath(keygen); err != nil {
		return "", "", &runner.Error{Kind: runner.KindExec, Err: fmt.Errorf("no se encontró %s en el equipo donde corre la aplicación", keygen)}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", "", err
	}
	if b, err := exec.CommandContext(ctx, keygen, "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", path).CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("ssh-keygen falló: %v: %s", err, strings.TrimSpace(string(b)))
	}
	b, err := os.ReadFile(path + ".pub")
	if err != nil {
		return "", "", err
	}
	pub = strings.TrimSpace(string(b))
	if !rePubKey.MatchString(pub) {
		return "", "", errors.New("la llave pública generada tiene un formato inesperado")
	}
	fp, _ := exec.CommandContext(ctx, keygen, "-l", "-f", path+".pub").Output()
	return pub, strings.TrimSpace(string(fp)), nil
}

// DeleteUserInput son los datos del formulario del punto 3.2.2.
type DeleteUserInput struct {
	Name        string
	RemoveFiles bool // borrar también el directorio personal y el correo
}

// DeleteUser implementa el punto 3.2.2. protected son cuentas que la
// aplicación usa para conectarse y que no se pueden eliminar desde aquí.
func DeleteUser(ctx context.Context, rn runner.Runner, in DeleteUserInput, protected ...string) *Result {
	o := newRun(ctx, rn, "usuarios")
	fail := func(msg string) *Result {
		o.res.Steps = append(o.res.Steps, Step{Name: "Validar los datos", Detail: msg})
		return o.res
	}
	if err := validate.Username(in.Name); err != nil {
		return fail(err.Error())
	}
	if validate.ReservedUser(in.Name) {
		return fail(fmt.Sprintf("%q es una cuenta del sistema y no se puede eliminar", in.Name))
	}
	for _, p := range protected {
		if p == in.Name {
			return fail(fmt.Sprintf("%q es el usuario con el que la aplicación se conecta a esta VM: eliminarlo cortaría el acceso", in.Name))
		}
	}
	u := runner.Quote(in.Name)

	// 1. Estado anterior: que exista, que no sea del sistema, y qué tiene.
	var home string
	if !o.step("Consultar el usuario "+in.Name, func() (string, string, error) {
		r, err := o.remote("consultar", `
u=`+u+`
e=$(getent passwd "$u") || { echo "el usuario $u no existe" >&2; exit 1; }
uid=$(echo "$e" | cut -d: -f3); h=$(echo "$e" | cut -d: -f6)
if [ "$uid" -lt 1000 ] || [ "$uid" -ge 65534 ]; then echo "$u (UID $uid) es una cuenta del sistema: no se elimina" >&2; exit 1; fi
echo "home=$h"
echo "$(id "$u")"
if [ -d "$h" ]; then echo "directorio personal: $h ($(du -sh "$h" 2>/dev/null | cut -f1))"; else echo "directorio personal: $h (no existe)"; fi
echo "procesos en ejecución: $(pgrep -u "$u" | wc -l)"
`, time.Minute)
		for _, l := range strings.Split(r.Stdout, "\n") {
			if strings.HasPrefix(l, "home=") {
				home = strings.TrimPrefix(l, "home=")
			}
		}
		lines := strings.Split(strings.TrimSpace(r.Stdout), "\n")
		if len(lines) > 1 {
			lines = lines[1:]
		}
		return strings.Join(lines, " · "), joinTech(r), err
	}) {
		return o.res
	}

	// 2. Eliminación. Se terminan sus procesos (userdel se niega si tiene
	// sesiones abiertas) y se quita su archivo de sudo si lo creó la aplicación.
	flag := ""
	if in.RemoveFiles {
		flag = "-r "
	}
	if !o.step("Eliminar el usuario"+map[bool]string{true: " y todos sus archivos", false: " (conservando sus archivos)"}[in.RemoveFiles], func() (string, string, error) {
		r, err := o.remote("eliminar", `
u=`+u+`
pkill -KILL -u "$u" 2>/dev/null && sleep 1 || true
rm -f `+runner.Quote(sudoersFile(in.Name))+`
userdel `+flag+`-- "$u"
echo "userdel `+flag+`$u: correcto"
`, 2*time.Minute)
		return firstLines(r.Stdout, 1), joinTech(r), err
	}) {
		return o.res
	}

	// 3. Verificación.
	if !o.step("Verificar la eliminación", func() (string, string, error) {
		r, err := o.remote("verificar", `
u=`+u+`
h=`+runner.Quote(home)+`
if id "$u" >/dev/null 2>&1; then echo "el usuario $u sigue existiendo" >&2; exit 1; fi
echo "el usuario $u ya no existe"
if [ -n "$h" ] && [ -e "$h" ]; then echo "archivos: $h se conserva"; else echo "archivos: $h eliminado"; fi
`, time.Minute)
		if err != nil {
			return "", joinTech(r), err
		}
		if in.RemoveFiles && strings.Contains(r.Stdout, "se conserva") {
			return "", joinTech(r), errors.New("el usuario se eliminó pero su directorio personal sigue en la VM")
		}
		return strings.Join(strings.Split(strings.TrimSpace(r.Stdout), "\n"), " · "), joinTech(r), nil
	}) {
		return o.res
	}
	return o.done()
}

// ListUsers muestra los usuarios normales (UID 1000 a 65533) de la VM: útil
// para mostrar el estado antes y después en las pruebas.
func ListUsers(ctx context.Context, rn runner.Runner) *Result {
	o := newRun(ctx, rn, "usuarios")
	if !o.step("Listar los usuarios de la VM", func() (string, string, error) {
		r, err := o.remote("listar", `
printf '%-16s %-6s %-22s %-5s %-11s %s\n' USUARIO UID DIRECTORIO SUDO CONTRASEÑA "LLAVES SSH"
getent passwd | awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' | sort | while read -r u; do
  e=$(getent passwd "$u"); uid=$(echo "$e" | cut -d: -f3); h=$(echo "$e" | cut -d: -f6)
  if id -nG "$u" | tr ' ' '\n' | grep -qx sudo; then s=sí; else s=no; fi
  case "$(passwd -S -- "$u" | awk '{print $2}')" in L) p=bloqueada ;; P) p=asignada ;; *) p=sin-asignar ;; esac
  k=$(grep -c '^ssh-' "$h/.ssh/authorized_keys" 2>/dev/null || true)
  printf '%-16s %-6s %-22s %-5s %-11s %s\n' "$u" "$uid" "$h" "$s" "$p" "${k:-0}"
done
`, time.Minute)
		if err == nil {
			o.res.Preview = strings.TrimRight(r.Stdout, "\n")
		}
		n := len(strings.Split(strings.TrimSpace(r.Stdout), "\n")) - 1
		return fmt.Sprintf("%d usuarios normales (UID ≥ 1000)", n), "", err
	}) {
		return o.res
	}
	return o.done()
}
