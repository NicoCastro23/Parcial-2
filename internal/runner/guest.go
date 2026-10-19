package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Guest ejecuta scripts dentro de la VM con las Guest Additions de
// VirtualBox (VBoxManage guestcontrol ... run). Es el canal del arranque
// inicial: antes de que SSH exista, es la única forma de hablar con la VM.
//
// Si User es "root" el script corre directamente. Si es otro usuario, se
// eleva con sudo usando Password.
//
// Limitación conocida: con un usuario no root la contraseña de sudo viaja
// como parte del comando dentro de la VM. Es aceptable en el laboratorio
// (red local, VM propia), pero por eso este canal solo se usa para instalar
// y configurar SSH.
type Guest struct {
	VBoxManage string // por defecto "VBoxManage"
	VM         string
	User       string
	Password   string
	TimeoutMs  int // por defecto 10 minutos
}

func (g *Guest) Transport() string { return "guest" }

func (g *Guest) Describe() string {
	return fmt.Sprintf("Guest Additions: VM %q, usuario %q", g.VM, g.User)
}

// BuildArgs devuelve los argumentos de VBoxManage. Se separa de Run para
// poder probarlo sin VirtualBox.
func (g *Guest) BuildArgs(passwordFile, script string) []string {
	timeout := g.TimeoutMs
	if timeout == 0 {
		timeout = 10 * 60 * 1000
	}
	body := prelude + script
	if g.User != "root" {
		if g.Password != "" {
			body = "printf '%s\\n' " + Quote(g.Password) + " | sudo -S -p '' bash -c " + Quote(body)
		} else {
			body = "sudo -n bash -c " + Quote(body)
		}
	}
	return []string{
		"guestcontrol", g.VM, "run",
		"--exe", "/bin/bash",
		"--username", g.User,
		"--passwordfile", passwordFile,
		"--wait-stdout", "--wait-stderr",
		"--timeout", strconv.Itoa(timeout),
		"--", "bash", "-c", body,
	}
}

func (g *Guest) Run(ctx context.Context, script string) (Result, error) {
	bin := g.VBoxManage
	if bin == "" {
		bin = "VBoxManage"
	}
	pw, err := os.CreateTemp("", "np2-guest-pw-*")
	if err != nil {
		return Result{Script: script}, &Error{Kind: KindExec, Err: err}
	}
	defer os.Remove(pw.Name())
	if err := pw.Chmod(0o600); err == nil {
		_, err = pw.WriteString(g.Password)
	}
	pw.Close()
	if err != nil {
		return Result{Script: script}, &Error{Kind: KindExec, Err: err}
	}

	cmd := exec.CommandContext(ctx, bin, g.BuildArgs(pw.Name(), script)...)
	res, runErr := execute(cmd)
	// Se describe el comando sin el script ni secretos.
	res.Command = fmt.Sprintf("%s guestcontrol %s run --username %s -- bash -c <script>", bin, g.VM, g.User)
	res.Script = script
	return res, classify(ctx, res, runErr, func(r Result) bool {
		// Errores de VBoxManage (VM apagada, Additions no activas, credenciales).
		return strings.Contains(r.Stderr, "VBoxManage: error:")
	})
}
