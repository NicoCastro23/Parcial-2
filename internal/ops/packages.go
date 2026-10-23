package ops

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"np2auto/internal/runner"
	"np2auto/internal/validate"
)

// Acciones del punto 3.1.1.
const (
	PkgInstall = "install"
	PkgRemove  = "remove"
)

// PackagesInput son los datos del formulario del punto 3.1.1.
type PackagesInput struct {
	Action   string   // PkgInstall o PkgRemove
	Packages []string // ya validados con validate.PackageList
	Purge    bool     // al eliminar, borrar también los archivos de configuración
}

// Validate vuelve a comprobar los datos (la web ya los validó; esta es la
// segunda barrera antes de armar los scripts).
func (in PackagesInput) Validate() error {
	if in.Action != PkgInstall && in.Action != PkgRemove {
		return fmt.Errorf("acción inválida %q", in.Action)
	}
	if len(in.Packages) == 0 {
		return errors.New("indique al menos un paquete")
	}
	if len(in.Packages) > 10 {
		return errors.New("indique como máximo 10 paquetes por operación")
	}
	for _, p := range in.Packages {
		if err := validate.PackageName(p); err != nil {
			return err
		}
	}
	return nil
}

// Opciones comunes de apt: no preguntar por archivos de configuración y
// esperar (en vez de fallar) si otro proceso, como apt-daily, tiene el bloqueo.
const aptOpts = `-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -o DPkg::Lock::Timeout=180`

// protectedPkgs son paquetes cuya eliminación dejaría la VM inaccesible para
// la aplicación (SSH, sudo, red) o sin arrancar. Se comprueban sobre la
// SIMULACIÓN de apt, así que también se detectan cuando caen por dependencia
// (p. ej. quitar openssh-client arrastra openssh-server).
var protectedPkgs = map[string]bool{
	"openssh-server": true, "openssh-client": true, "openssh-sftp-server": true, "ssh": true,
	"sudo": true, "systemd": true, "systemd-sysv": true, "init": true, "udev": true,
	"apt": true, "dpkg": true, "bash": true, "coreutils": true, "login": true, "passwd": true,
	"libc6": true, "base-files": true, "ifupdown": true, "isc-dhcp-client": true, "dhcpcd-base": true,
	"network-manager": true, "systemd-resolved": true,
}

var protectedPrefixes = []string{"linux-image-", "grub-", "virtualbox-guest-"}

func isProtected(pkg string) bool {
	if protectedPkgs[pkg] {
		return true
	}
	for _, p := range protectedPrefixes {
		if strings.HasPrefix(pkg, p) {
			return true
		}
	}
	return false
}

// pkgState es el estado de un paquete según dpkg.
type pkgState struct {
	State   string // "instalado", "no-instalado", "configuracion-residual" u otro
	Version string
}

func (s pkgState) installed() bool { return s.State == "instalado" }

func (s pkgState) String() string {
	switch s.State {
	case "instalado":
		return "instalado (" + s.Version + ")"
	case "configuracion-residual":
		return "no instalado (quedan archivos de configuración)"
	case "no-instalado":
		return "no instalado"
	default:
		return "estado " + s.State
	}
}

// pkgStateScript imprime una línea "paquete<TAB>estado<TAB>versión" por paquete.
func pkgStateScript(pkgs []string) string {
	q := make([]string, len(pkgs))
	for i, p := range pkgs {
		q[i] = runner.Quote(p)
	}
	return `
for p in ` + strings.Join(q, " ") + `; do
  s=$(dpkg-query -W -f='${db:Status-Abbrev}|${Version}' "$p" 2>/dev/null || true)
  st=${s%%|*}; st=$(printf '%s' "$st" | tr -d ' ')
  case "$st" in
    ii) printf '%s\tinstalado\t%s\n' "$p" "${s#*|}" ;;
    rc) printf '%s\tconfiguracion-residual\t\n' "$p" ;;
    ""|un|pn) printf '%s\tno-instalado\t\n' "$p" ;;
    *) printf '%s\t%s\t%s\n' "$p" "$st" "${s#*|}" ;;
  esac
done
`
}

func parsePkgStates(out string) map[string]pkgState {
	m := map[string]pkgState{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\t")
		if len(f) >= 2 && f[0] != "" {
			st := pkgState{State: f[1]}
			if len(f) >= 3 {
				st.Version = f[2]
			}
			m[f[0]] = st
		}
	}
	return m
}

func describeStates(pkgs []string, m map[string]pkgState) string {
	parts := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		st, ok := m[p]
		if !ok {
			st = pkgState{State: "desconocido"}
		}
		parts = append(parts, p+": "+st.String())
	}
	return strings.Join(parts, " · ")
}

// parseSimulatedRemovals extrae los paquetes que apt eliminaría ("Remv x
// [versión]" o "Purg x [versión]") de la salida de apt-get -s.
func parseSimulatedRemovals(out string) []string {
	var r []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && (f[0] == "Remv" || f[0] == "Purg") {
			r = append(r, f[1])
		}
	}
	sort.Strings(r)
	return r
}

// PackagesState consulta el estado de los paquetes sin cambiar nada.
func PackagesState(ctx context.Context, rn runner.Runner, pkgs []string) *Result {
	o := newRun(ctx, rn, "paquetes")
	if !o.step("Consultar el estado de los paquetes", func() (string, string, error) {
		r, err := o.remote("consultar", pkgStateScript(pkgs), time.Minute)
		return describeStates(pkgs, parsePkgStates(r.Stdout)), joinTech(r), err
	}) {
		return o.res
	}
	return o.done()
}

// ManagePackages implementa el punto 3.1.1: instala o elimina paquetes con
// apt de forma no interactiva y comprueba el resultado con dpkg.
func ManagePackages(ctx context.Context, rn runner.Runner, in PackagesInput) *Result {
	o := newRun(ctx, rn, "paquetes")
	if err := in.Validate(); err != nil {
		o.res.Steps = append(o.res.Steps, Step{Name: "Validar los datos", Detail: err.Error()})
		return o.res
	}
	list := strings.Join(in.Packages, " ")
	quoted := make([]string, len(in.Packages))
	for i, p := range in.Packages {
		quoted[i] = runner.Quote(p)
	}
	args := strings.Join(quoted, " ")

	// 1. Estado anterior.
	var before map[string]pkgState
	if !o.step("Consultar el estado anterior", func() (string, string, error) {
		r, err := o.remote("antes", pkgStateScript(in.Packages), time.Minute)
		before = parsePkgStates(r.Stdout)
		return describeStates(in.Packages, before), joinTech(r), err
	}) {
		return o.res
	}

	if in.Action == PkgInstall {
		// 2. Índice de paquetes al día, para que apt encuentre las versiones actuales.
		if !o.step("Actualizar el índice de paquetes (apt-get update)", func() (string, string, error) {
			r, err := o.remote("update", `apt-get update -q `+aptOpts, 5*time.Minute)
			return "Índice actualizado", joinTech(r), err
		}) {
			return o.res
		}

		// 3. Que existan en los repositorios: mensaje claro en vez del error de apt.
		if !o.step("Comprobar que los paquetes existan en los repositorios", func() (string, string, error) {
			r, err := o.remote("existe", `
for p in `+args+`; do
  c=$(apt-cache policy "$p" 2>/dev/null | awk '/Candidate:/ {print $2}')
  if [ -z "$c" ] || [ "$c" = "(none)" ]; then echo "$p"; fi
done
`, time.Minute)
			if err != nil {
				return "", joinTech(r), err
			}
			if missing := strings.Fields(r.Stdout); len(missing) > 0 {
				return "", joinTech(r), fmt.Errorf("no se encontró en los repositorios configurados: %s. Revise el nombre (p. ej. con apt search) o si es un paquete virtual", strings.Join(missing, ", "))
			}
			return "Todos los paquetes tienen una versión disponible", joinTech(r), nil
		}) {
			return o.res
		}

		// 4. Instalación.
		if !o.step("Instalar "+list, func() (string, string, error) {
			r, err := o.remote("instalar", `apt-get install -y -q `+aptOpts+` -- `+args, 20*time.Minute)
			return aptSummary(r.Stdout), joinTech(r), err
		}) {
			return o.res
		}
	} else {
		// Solo se eliminan los que están instalados; apt falla con nombres que
		// no conoce, y no tiene sentido pedirle quitar lo que no está.
		var toRemove, skipped []string
		for _, p := range in.Packages {
			st := before[p]
			if st.installed() || (in.Purge && st.State == "configuracion-residual") {
				toRemove = append(toRemove, p)
			} else {
				skipped = append(skipped, p)
			}
		}
		if len(toRemove) == 0 {
			o.res.Steps = append(o.res.Steps, Step{Name: "Eliminar " + list, OK: true,
				Detail: "Ninguno de los paquetes estaba instalado: no hay nada que eliminar."})
			return o.done()
		}
		verb := "remove"
		if in.Purge {
			verb = "purge"
		}
		rq := make([]string, len(toRemove))
		for i, p := range toRemove {
			rq[i] = runner.Quote(p)
		}
		rargs := strings.Join(rq, " ")

		// 2. Simulación: qué se eliminaría realmente, incluidas dependencias.
		if !o.step("Simular la eliminación (apt-get -s "+verb+")", func() (string, string, error) {
			r, err := o.remote("simular", `apt-get -s `+verb+` `+aptOpts+` -- `+rargs, 2*time.Minute)
			if err != nil {
				return "", joinTech(r), err
			}
			removed := parseSimulatedRemovals(r.Stdout)
			var blocked []string
			for _, p := range removed {
				if isProtected(p) {
					blocked = append(blocked, p)
				}
			}
			if len(blocked) > 0 {
				return "", joinTech(r), fmt.Errorf("se canceló: la eliminación quitaría %s, necesarios para que la aplicación siga administrando la VM (SSH, sudo, red o arranque)", strings.Join(blocked, ", "))
			}
			d := "Se eliminará: " + strings.Join(removed, ", ")
			if len(skipped) > 0 {
				d += ". No estaban instalados: " + strings.Join(skipped, ", ")
			}
			return d, joinTech(r), nil
		}) {
			return o.res
		}

		// 3. Eliminación.
		if !o.step("Eliminar "+strings.Join(toRemove, " "), func() (string, string, error) {
			r, err := o.remote("eliminar", `apt-get `+verb+` -y -q `+aptOpts+` -- `+rargs, 15*time.Minute)
			return aptSummary(r.Stdout), joinTech(r), err
		}) {
			return o.res
		}
	}

	// Verificación con dpkg: el estado final es el que se pidió.
	if !o.step("Verificar el estado final", func() (string, string, error) {
		r, err := o.remote("verificar", pkgStateScript(in.Packages), time.Minute)
		if err != nil {
			return "", joinTech(r), err
		}
		after := parsePkgStates(r.Stdout)
		var wrong []string
		for _, p := range in.Packages {
			st := after[p]
			switch {
			case in.Action == PkgInstall && !st.installed():
				wrong = append(wrong, p+" sigue sin instalarse")
			case in.Action == PkgRemove && st.installed():
				wrong = append(wrong, p+" sigue instalado")
			case in.Action == PkgRemove && in.Purge && st.State == "configuracion-residual":
				wrong = append(wrong, p+" conserva archivos de configuración")
			}
		}
		if len(wrong) > 0 {
			return "", joinTech(r), errors.New("El estado final no es el esperado: " + strings.Join(wrong, "; "))
		}
		return "Antes: " + describeStates(in.Packages, before) + " → Después: " + describeStates(in.Packages, after), joinTech(r), nil
	}) {
		return o.res
	}
	return o.done()
}

// aptSummary devuelve la línea de resumen de apt ("N upgraded, N newly
// installed, N to remove...") o, si no está, la última línea.
func aptSummary(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "newly installed") {
			return strings.TrimSpace(line)
		}
	}
	return lastLine(out)
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}
