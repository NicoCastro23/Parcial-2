package ops

import (
	"context"
	"fmt"
	"strings"
	"time"

	"np2auto/internal/runner"
	"np2auto/internal/validate"
)

// HostnameInput son los datos del formulario del punto 3.1.4.
type HostnameInput struct {
	Name   string // nombre corto, p. ej. "web1"
	Domain string // dominio opcional, p. ej. "lab.local"
}

// FQDN devuelve el nombre completo (nombre.dominio) o "" si no hay dominio.
func (in HostnameInput) FQDN() string {
	if in.Domain == "" {
		return ""
	}
	return in.Name + "." + in.Domain
}

// hostsEntry es lo que va después de 127.0.1.1 en /etc/hosts. Debian pone
// primero el nombre completo y luego el corto.
func (in HostnameInput) hostsEntry() string {
	if f := in.FQDN(); f != "" {
		return f + " " + in.Name
	}
	return in.Name
}

// Validate comprueba ambos campos con las listas blancas de validate.
func (in HostnameInput) Validate() error {
	if err := validate.Hostname(in.Name); err != nil {
		return err
	}
	if in.Domain != "" {
		if err := validate.Domain(in.Domain); err != nil {
			return err
		}
	}
	return nil
}

const hostsFile = "/etc/hosts"

// hostnameStateScript muestra el estado que el punto 3.1.4 modifica. Se usa
// antes y después de aplicar el cambio, para que se vea la diferencia.
const hostnameStateScript = `
echo "nombre de host: $(hostname)"
echo "/etc/hostname: $(cat /etc/hostname 2>/dev/null || echo '(no existe)')"
l=$(grep -E '^127\.0\.1\.1[[:space:]]' /etc/hosts || true)
echo "/etc/hosts: ${l:-sin línea 127.0.1.1}"
echo "--- /etc/hosts ---"
cat /etc/hosts
`

// HostnameState consulta el nombre de host y /etc/hosts sin cambiar nada.
func HostnameState(ctx context.Context, rn runner.Runner) *Result {
	o := newRun(ctx, rn, "hostname")
	if !o.step("Consultar el nombre de host y /etc/hosts", func() (string, string, error) {
		r, err := o.remote("consultar", hostnameStateScript, time.Minute)
		return firstLines(r.Stdout, 3), joinTech(r), err
	}) {
		return o.res
	}
	return o.done()
}

// SetHostname implementa el punto 3.1.4: asigna el nombre de host y
// actualiza /etc/hosts para que el nombre nuevo resuelva a 127.0.1.1
// (convención de Debian).
func SetHostname(ctx context.Context, rn runner.Runner, in HostnameInput) *Result {
	o := newRun(ctx, rn, "hostname")
	if err := in.Validate(); err != nil {
		o.res.Steps = append(o.res.Steps, Step{Name: "Validar los datos", Detail: err.Error()})
		return o.res
	}

	// 1. Estado anterior (evidencia del "antes").
	var before string
	if !o.step("Consultar el estado anterior", func() (string, string, error) {
		r, err := o.remote("antes", hostnameStateScript, time.Minute)
		before = firstLine(r.Stdout)
		return firstLines(r.Stdout, 3), joinTech(r), err
	}) {
		return o.res
	}

	// 2. Nombre de host. hostnamectl lo cambia en caliente y en /etc/hostname;
	// si no está disponible se hace a mano.
	if !o.step("Asignar el nombre de host "+in.Name, func() (string, string, error) {
		r, err := o.remote("asignar", `
new=`+runner.Quote(in.Name)+`
if command -v hostnamectl >/dev/null 2>&1 && hostnamectl set-hostname "$new"; then
  echo "hostnamectl set-hostname $new"
else
  printf '%s\n' "$new" > /etc/hostname
  hostname "$new"
  echo "escrito en /etc/hostname y aplicado con hostname"
fi
`, time.Minute)
		return firstLines(r.Stdout, 1), joinTech(r), err
	}) {
		return o.res
	}

	// 3. /etc/hosts.
	if !o.step("Actualizar /etc/hosts", func() (string, string, error) {
		r, err := o.remote("hosts", hostsUpdateScript(hostsFile, in.hostsEntry()), time.Minute)
		return firstLines(r.Stdout, 2), joinTech(r), err
	}) {
		return o.res
	}

	// 4. Verificación: el nombre quedó aplicado y resuelve localmente.
	if !o.step("Verificar el resultado", func() (string, string, error) {
		r, err := o.remote("verificar", `
new=`+runner.Quote(in.Name)+`
[ "$(hostname)" = "$new" ] || { echo "hostname devuelve $(hostname), se esperaba $new" >&2; exit 1; }
[ "$(cat /etc/hostname)" = "$new" ] || { echo "/etc/hostname no contiene $new" >&2; exit 1; }
getent ahostsv4 "$new" | grep -q '^127\.0\.1\.1 ' || { echo "$new no resuelve a 127.0.1.1" >&2; exit 1; }
`+hostnameStateScript, time.Minute)
		after := firstLine(r.Stdout)
		detail := fmt.Sprintf("Antes: %s → Después: %s. El nombre resuelve a 127.0.1.1.", strings.TrimPrefix(before, "nombre de host: "), strings.TrimPrefix(after, "nombre de host: "))
		return detail, joinTech(r), err
	}) {
		return o.res
	}
	return o.done()
}

// hostsUpdateScript deja una sola línea "127.0.1.1 <entry>" en el archivo:
// reemplaza la existente o, si no hay, la agrega después de 127.0.0.1. Guarda
// una copia del archivo anterior. entry ya viene validado (solo minúsculas,
// dígitos, puntos, guiones y un espacio).
func hostsUpdateScript(path, entry string) string {
	return `
f=` + runner.Quote(path) + `
entry=` + runner.Quote(entry) + `
cp -p "$f" "$f.np2-prev"
tmp=$(mktemp)
if grep -qE '^127\.0\.1\.1[[:space:]]' "$f"; then
  awk -v e="$entry" '/^127\.0\.1\.1[ \t]/ { if (!d) { print "127.0.1.1\t" e; d = 1 }; next } { print }' "$f" > "$tmp"
  echo "línea 127.0.1.1 reemplazada"
else
  awk -v e="$entry" '{ print } /^127\.0\.0\.1[ \t]/ && !d { print "127.0.1.1\t" e; d = 1 } END { if (!d) print "127.0.1.1\t" e }' "$f" > "$tmp"
  echo "línea 127.0.1.1 agregada"
fi
cat "$tmp" > "$f"
rm -f "$tmp"
grep -E '^127\.0\.1\.1[[:space:]]' "$f"
echo "copia del archivo anterior: $f.np2-prev"
`
}

func firstLine(s string) string { return firstLines(s, 1) }
