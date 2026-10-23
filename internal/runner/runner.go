// Package runner ejecuta scripts como root en una máquina virtual.
//
// Hay dos transportes, igual que pide el enunciado:
//   - Guest: Guest Additions (VBoxManage guestcontrol). Se usa solo antes de
//     que SSH esté instalado y configurado con llaves.
//   - SSH: SSH con llaves de autenticación, sin contraseñas. Es el único
//     canal una vez configurado SSH.
//
// Ambos implementan la interfaz Runner, de modo que los módulos de
// automatización (paquetes, usuarios, systemd, HAProxy...) no dependen del
// canal.
package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
)

// prelude se antepone a todo script: sin preguntas interactivas de apt y
// terminación inmediata ante errores o variables sin definir.
const prelude = "export DEBIAN_FRONTEND=noninteractive LC_ALL=C.UTF-8\nset -eu\n"

// Runner ejecuta un script de shell (bash) con privilegios de root.
type Runner interface {
	// Transport devuelve "ssh" o "guest".
	Transport() string
	// Describe devuelve una descripción legible del destino, sin secretos.
	Describe() string
	// Run ejecuta el script. Devuelve un *Error si algo falla, incluido un
	// código de salida distinto de cero; el Result siempre viene completo.
	Run(ctx context.Context, script string) (Result, error)
}

// Uploader lo implementan los canales que pueden enviar datos al script por
// la entrada estándar (hoy solo SSH: la transferencia de archivos ocurre
// cuando la VM ya se administra por SSH).
type Uploader interface {
	RunInput(ctx context.Context, script string, in io.Reader) (Result, error)
}

// Result es la evidencia técnica de una ejecución.
type Result struct {
	Command  string        `json:"command"`
	Script   string        `json:"script"`
	Stdout   string        `json:"stdout"`
	Stderr   string        `json:"stderr"`
	ExitCode int           `json:"exit_code"`
	Duration time.Duration `json:"duration_ns"`
	Started  time.Time     `json:"started"`
}

// Kind clasifica un fallo.
type Kind string

const (
	KindExec    Kind = "exec"    // no se pudo lanzar la herramienta local (ssh, VBoxManage)
	KindConnect Kind = "connect" // no se logró comunicar con la VM
	KindExit    Kind = "exit"    // el script terminó con código distinto de cero
	KindTimeout Kind = "timeout" // tiempo agotado o cancelación
)

// Error es el error de una ejecución; conserva el Result para diagnóstico.
type Error struct {
	Kind   Kind
	Result Result
	Err    error
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %v", e.Kind, e.Err) }
func (e *Error) Unwrap() error { return e.Err }

// Explain devuelve un mensaje comprensible para el usuario a partir de un
// error de Run. El detalle técnico completo está en Error.Result.
func Explain(err error) string {
	var re *Error
	if !errors.As(err, &re) {
		return err.Error()
	}
	detail := lastLine(re.Result.Stderr)
	if detail == "" {
		detail = lastLine(re.Result.Stdout)
	}
	switch re.Kind {
	case KindExec:
		return "No se pudo ejecutar la herramienta local: " + re.Err.Error()
	case KindTimeout:
		return "La operación superó el tiempo límite o fue cancelada."
	case KindConnect:
		msg := "No se pudo comunicar con la máquina virtual. Verifique que esté encendida, que la dirección IP sea la correcta y que la llave (SSH) o las credenciales (Guest Additions) sean válidas."
		if detail != "" {
			msg += " Detalle: " + detail
		}
		return msg
	default:
		msg := fmt.Sprintf("El comando terminó con código de salida %d.", re.Result.ExitCode)
		if detail != "" {
			msg += " Detalle: " + detail
		}
		return msg
	}
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

// capBuffer limita la salida capturada para no agotar la memoria.
type capBuffer struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (c *capBuffer) Write(p []byte) (int, error) {
	room := c.max - c.buf.Len()
	if room <= 0 {
		c.truncated = true
		return len(p), nil
	}
	if len(p) > room {
		c.buf.Write(p[:room])
		c.truncated = true
		return len(p), nil
	}
	return c.buf.Write(p)
}

func (c *capBuffer) String() string {
	if c.truncated {
		return c.buf.String() + "\n[salida truncada]"
	}
	return c.buf.String()
}

const maxOutput = 1 << 20 // 1 MiB por flujo

// execute corre el comando capturando salida y tiempos.
func execute(cmd *exec.Cmd) (Result, error) {
	var out, errb capBuffer
	out.max, errb.max = maxOutput, maxOutput
	cmd.Stdout, cmd.Stderr = &out, &errb
	cmd.WaitDelay = 5 * time.Second
	start := time.Now()
	err := cmd.Run()
	res := Result{
		Started:  start,
		Duration: time.Since(start),
		Stdout:   out.String(),
		Stderr:   errb.String(),
	}
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		res.ExitCode = ee.ExitCode()
	case err != nil:
		res.ExitCode = -1
	}
	return res, err
}

// classify convierte el error crudo de exec en un *Error con su Kind.
func classify(ctx context.Context, res Result, err error, isConnect func(Result) bool) error {
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return &Error{Kind: KindTimeout, Result: res, Err: ctx.Err()}
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return &Error{Kind: KindExec, Result: res, Err: err}
	}
	if isConnect(res) {
		return &Error{Kind: KindConnect, Result: res, Err: err}
	}
	return &Error{Kind: KindExit, Result: res, Err: err}
}

// Quote escapa una cadena para usarla como un único argumento de shell.
// Es la segunda barrera de seguridad, además de validate.
func Quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
