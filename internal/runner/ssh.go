package runner

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os/exec"
	"strconv"
)

// SSH ejecuta scripts en la VM mediante el cliente ssh del sistema, siempre
// con llaves de autenticación (BatchMode: nunca pregunta contraseñas).
//
// Se usa el binario ssh del sistema en lugar de una biblioteca para que la
// aplicación no tenga dependencias externas y respete el mismo
// comportamiento que el estudiante prueba a mano en la terminal.
type SSH struct {
	Host           string
	Port           int
	User           string
	KeyPath        string
	KnownHosts     string // archivo propio de la aplicación; vacío = el del usuario
	Bin            string // por defecto "ssh"
	ConnectTimeout int    // segundos; por defecto 8
	// NoSudo ejecuta el script como el propio usuario aunque no sea root
	// (sirve para comprobar el acceso de un usuario recién creado).
	NoSudo bool
}

func (s *SSH) Transport() string { return "ssh" }

func (s *SSH) Describe() string {
	return fmt.Sprintf("ssh %s@%s:%d (llave %s)", s.User, s.Host, s.port(), s.KeyPath)
}

func (s *SSH) port() int {
	if s.Port == 0 {
		return 22
	}
	return s.Port
}

func (s *SSH) args(remote string) []string {
	ct := s.ConnectTimeout
	if ct == 0 {
		ct = 8
	}
	a := []string{
		"-i", s.KeyPath,
		"-p", strconv.Itoa(s.port()),
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
		// Confianza en el primer uso (TOFU): se registra la huella la primera
		// vez y se rechaza si cambia después.
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "ConnectTimeout=" + strconv.Itoa(ct),
		"-o", "ServerAliveInterval=15",
		"-o", "LogLevel=ERROR",
	}
	if s.KnownHosts != "" {
		a = append(a, "-o", "UserKnownHostsFile="+s.KnownHosts)
	}
	return append(a, "--", s.User+"@"+s.Host, remote)
}

// remoteCommand arma el comando remoto. El script viaja codificado en base64
// como argumento: así no hay problemas de comillas y la entrada estándar
// queda libre (un comando como apt no puede "comerse" el resto del script).
func remoteCommand(script string, sudo bool) string {
	b64 := base64.StdEncoding.EncodeToString([]byte(prelude + script))
	cmd := `bash -c "$(printf %s ` + b64 + ` | base64 -d)"`
	if sudo {
		return "sudo -n " + cmd
	}
	return cmd
}

func (s *SSH) Run(ctx context.Context, script string) (Result, error) {
	return s.RunInput(ctx, script, nil)
}

// RunInput ejecuta el script enviándole in por la entrada estándar. Sirve
// para transferir archivos (un tar) por la misma conexión SSH.
func (s *SSH) RunInput(ctx context.Context, script string, in io.Reader) (Result, error) {
	bin := s.Bin
	if bin == "" {
		bin = "ssh"
	}
	cmd := exec.CommandContext(ctx, bin, s.args(remoteCommand(script, s.User != "root" && !s.NoSudo))...)
	cmd.Stdin = in
	res, err := execute(cmd)
	res.Command = s.Describe()
	res.Script = script
	// ssh devuelve 255 cuando falla la conexión o la autenticación.
	return res, classify(ctx, res, err, func(r Result) bool { return r.ExitCode == 255 })
}
