package ops

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"np2auto/internal/runner"
	"np2auto/internal/validate"
)

// IssueInput son los datos del formulario del punto 3.1.3. Cada casilla
// agrega una línea con la secuencia de escape de agetty correspondiente; el
// valor real lo pone agetty cada vez que muestra la pantalla de entrada.
type IssueInput struct {
	Message  string // mensaje personalizado (una línea, sin barra invertida)
	Color    bool   // resaltar el mensaje (negrita y color)
	Hostname bool   // \n
	Date     bool   // \d
	Time     bool   // \t
	IP       bool   // \4: IPv4 de la primera interfaz activa
	System   bool   // \S{PRETTY_NAME}
	Kernel   bool   // \r (\m)
	TTY      bool   // \l
	Users    bool   // \u
}

// issueField relaciona una casilla con su línea en /etc/issue.
type issueField struct {
	on    bool
	label string
	esc   string
}

func (in IssueInput) fields() []issueField {
	return []issueField{
		{in.Hostname, "Equipo", `\n`},
		{in.Date, "Fecha", `\d`},
		{in.Time, "Hora", `\t`},
		{in.IP, "Dirección IP", `\4`},
		{in.System, "Sistema", `\S{PRETTY_NAME}`},
		{in.Kernel, "Núcleo", `\r (\m)`},
		{in.TTY, "Terminal", `\l`},
		{in.Users, "Usuarios conectados", `\u`},
	}
}

// Validate exige un mensaje válido o al menos una casilla.
func (in IssueInput) Validate() error {
	if _, err := validate.IssueText(in.Message); err != nil {
		return err
	}
	if strings.TrimSpace(in.Message) == "" {
		for _, f := range in.fields() {
			if f.on {
				return nil
			}
		}
		return errors.New("escriba un mensaje o marque al menos un dato para mostrar")
	}
	return nil
}

// Content arma el contenido de /etc/issue.
func (in IssueInput) Content() string {
	var b strings.Builder
	b.WriteString("\n")
	if msg := strings.TrimSpace(in.Message); msg != "" {
		if in.Color {
			b.WriteString(`  \e{bold}\e{cyan}` + msg + `\e{reset}` + "\n\n")
		} else {
			b.WriteString("  " + msg + "\n\n")
		}
	}
	width := 0
	for _, f := range in.fields() {
		if f.on && len([]rune(f.label)) > width {
			width = len([]rune(f.label))
		}
	}
	any := false
	for _, f := range in.fields() {
		if f.on {
			pad := strings.Repeat(" ", width-len([]rune(f.label)))
			b.WriteString("  " + f.label + ":" + pad + " " + f.esc + "\n")
			any = true
		}
	}
	if any {
		b.WriteString("\n")
	}
	return b.String()
}

const issueFile = "/etc/issue"

// issueRenderScript muestra cómo se verá la pantalla de entrada. agetty
// necesita una terminal, así que se le da una con script(1).
const issueRenderScript = `
if command -v agetty >/dev/null 2>&1 && command -v script >/dev/null 2>&1; then
  timeout 10 script -qec "agetty --show-issue" /dev/null </dev/null || echo "(agetty no pudo mostrar la vista previa)"
else
  echo "(agetty o script no están disponibles para la vista previa)"
fi
`

var reANSI = regexp.MustCompile("\x1b\\[[0-9;]*[A-Za-z]")

// cleanTerminal quita retornos de carro y códigos de color de la salida de
// agetty para mostrarla en la página.
func cleanTerminal(s string) string {
	s = reANSI.ReplaceAllString(s, "")
	return strings.ReplaceAll(s, "\r", "")
}

// IssueState muestra el contenido actual de /etc/issue y cómo se ve.
func IssueState(ctx context.Context, rn runner.Runner) *Result {
	o := newRun(ctx, rn, "issue")
	if !o.step("Consultar /etc/issue", func() (string, string, error) {
		r, err := o.remote("consultar", `cat /etc/issue`, time.Minute)
		return summarizeIssue(r.Stdout), joinTech(r), err
	}) {
		return o.res
	}
	o.preview()
	return o.done()
}

// SetIssue implementa el punto 3.1.3: escribe /etc/issue con el mensaje y
// los datos elegidos, y muestra cómo queda en la consola.
func SetIssue(ctx context.Context, rn runner.Runner, in IssueInput) *Result {
	o := newRun(ctx, rn, "issue")
	if err := in.Validate(); err != nil {
		o.res.Steps = append(o.res.Steps, Step{Name: "Validar los datos", Detail: err.Error()})
		return o.res
	}
	content := in.Content()

	// 1. Estado anterior.
	if !o.step("Consultar el contenido anterior de /etc/issue", func() (string, string, error) {
		r, err := o.remote("antes", `cat /etc/issue`, time.Minute)
		return summarizeIssue(r.Stdout), joinTech(r), err
	}) {
		return o.res
	}

	// 2. Escritura con copias de respaldo.
	if !o.step("Escribir /etc/issue", func() (string, string, error) {
		r, err := o.remote("escribir", issueWriteScript(issueFile, content), time.Minute)
		return firstLines(r.Stdout, 2), joinTech(r), err
	}) {
		return o.res
	}

	// 3. Verificación: el archivo tiene exactamente lo que se pidió.
	if !o.step("Verificar el contenido", func() (string, string, error) {
		r, err := o.remote("verificar", `cat /etc/issue`, time.Minute)
		if err != nil {
			return "", joinTech(r), err
		}
		if r.Stdout != content {
			return "", joinTech(r), errors.New("el contenido de /etc/issue no coincide con el que se escribió")
		}
		return "El archivo contiene exactamente la configuración elegida", joinTech(r), nil
	}) {
		return o.res
	}

	// 4. Vista previa con valores reales y actualización de las consolas.
	o.preview()
	return o.done()
}

// RestoreIssue devuelve /etc/issue al contenido que tenía antes de que la
// aplicación lo modificara por primera vez (/etc/issue.np2-orig).
func RestoreIssue(ctx context.Context, rn runner.Runner) *Result {
	o := newRun(ctx, rn, "issue")
	if !o.step("Restaurar el /etc/issue original", func() (string, string, error) {
		r, err := o.remote("restaurar", issueRestoreScript(issueFile), time.Minute)
		return firstLines(r.Stdout, 1), joinTech(r), err
	}) {
		return o.res
	}
	o.preview()
	return o.done()
}

// issueWriteScript guarda el original una sola vez (.np2-orig, para poder
// restaurarlo), la versión anterior en cada cambio (.np2-prev) y escribe el
// contenido nuevo. El contenido viaja entre comillas simples y se escribe con
// printf '%s', así que las barras invertidas de agetty llegan literales.
func issueWriteScript(path, content string) string {
	return `
f=` + runner.Quote(path) + `
[ -f "$f.np2-orig" ] || cp -p "$f" "$f.np2-orig"
cp -p "$f" "$f.np2-prev"
printf '%s' ` + runner.Quote(content) + ` > "$f"
chmod 644 "$f"
echo "/etc/issue actualizado"
echo "copias: $f.np2-prev (anterior) y $f.np2-orig (original)"
`
}

func issueRestoreScript(path string) string {
	return `
f=` + runner.Quote(path) + `
[ -f "$f.np2-orig" ] || { echo "no hay copia del original: la aplicación todavía no ha modificado $f" >&2; exit 1; }
cp -p "$f" "$f.np2-prev"
cat "$f.np2-orig" > "$f"
echo "se restauró el contenido original de $f"
`
}

// summarizeIssue resume el archivo en una línea para el detalle del paso.
func summarizeIssue(s string) string {
	var lines []string
	for _, l := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(l); t != "" {
			lines = append(lines, t)
		}
	}
	if len(lines) == 0 {
		return "(vacío)"
	}
	if len(lines) > 4 {
		lines = append(lines[:4], "…")
	}
	return strings.Join(lines, " · ")
}

// preview pide a agetty la pantalla de entrada con los valores reales y la
// deja en Result.Preview. También avisa a las consolas abiertas para que
// muestren el cambio sin reiniciar. Es solo informativo: si falla, la
// operación no se marca como fallida.
func (o *opRun) preview() {
	o.step("Mostrar cómo se ve en la consola y actualizarla", func() (string, string, error) {
		r, err := o.remote("vista", issueRenderScript+"agetty --reload 2>/dev/null || true\n", time.Minute)
		if err != nil {
			return "", joinTech(r), err
		}
		o.res.Preview = strings.Trim(cleanTerminal(r.Stdout), "\n")
		return "Vista previa abajo, con los valores reales de la VM. Las consolas que muestran el inicio de sesión se actualizaron.", "", nil
	})
}
