// Package validate centraliza la validación de todo dato que el usuario
// escribe en la interfaz web antes de que se use en un comando.
//
// La aplicación ejecuta comandos como root en las máquinas virtuales, así que
// cada entrada se valida con listas blancas estrictas (nunca con listas
// negras) y, además, se escapa al incrustarla en un script (ver
// runner.Quote). Son dos barreras independientes.
package validate

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	rePackage = regexp.MustCompile(`^[a-z0-9][a-z0-9+.\-]{1,99}$`)
	reUser    = regexp.MustCompile(`^[a-z_][a-z0-9_\-]{0,31}$`)
	reLabel   = regexp.MustCompile(`^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$`)
	reUnit    = regexp.MustCompile(`^[A-Za-z0-9_@][A-Za-z0-9:_.@\-]{0,99}$`)
	reServer  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.\-]{0,31}$`)
	reID      = regexp.MustCompile(`^[a-z0-9][a-z0-9_\-]{0,31}$`)
)

// reservedUsers son cuentas del sistema que la interfaz nunca debe crear ni
// eliminar.
var reservedUsers = map[string]bool{
	"root": true, "daemon": true, "bin": true, "sys": true, "sync": true,
	"games": true, "man": true, "lp": true, "mail": true, "news": true,
	"uucp": true, "proxy": true, "www-data": true, "backup": true,
	"list": true, "irc": true, "nobody": true, "sshd": true, "haproxy": true,
	"_apt": true, "messagebus": true,
}

// ID valida el identificador interno de un destino (VM) en la configuración.
func ID(s string) error {
	if !reID.MatchString(s) {
		return fmt.Errorf("identificador inválido %q: use minúsculas, dígitos, guion o guion bajo (máx. 32)", s)
	}
	return nil
}

// PackageName valida un único nombre de paquete de Debian.
func PackageName(s string) error {
	if !rePackage.MatchString(s) {
		return fmt.Errorf("nombre de paquete inválido %q: use minúsculas, dígitos, + - . (2 a 100 caracteres)", s)
	}
	return nil
}

// PackageList valida una lista de paquetes separados por espacios o comas
// (máximo 10) y devuelve la lista sin duplicados.
func PackageList(s string) ([]string, error) {
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
	if len(fields) == 0 {
		return nil, errors.New("indique al menos un paquete")
	}
	if len(fields) > 10 {
		return nil, errors.New("indique como máximo 10 paquetes por operación")
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if err := PackageName(f); err != nil {
			return nil, err
		}
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out, nil
}

// Username valida el formato de un nombre de usuario de Linux.
func Username(s string) error {
	if !reUser.MatchString(s) {
		return fmt.Errorf("nombre de usuario inválido %q: comience con letra minúscula o _, use minúsculas, dígitos, _ o - (máx. 32)", s)
	}
	return nil
}

// ReservedUser indica si el nombre pertenece a una cuenta del sistema que no
// debe crearse ni eliminarse desde la interfaz.
func ReservedUser(s string) bool { return reservedUsers[s] }

// Hostname valida un nombre de host (una etiqueta RFC 1123, sin puntos).
func Hostname(s string) error {
	if !reLabel.MatchString(s) {
		return fmt.Errorf("nombre de host inválido %q: use minúsculas, dígitos y guiones; no puede comenzar ni terminar con guion (máx. 63)", s)
	}
	return nil
}

// Port convierte y valida un número de puerto TCP.
func Port(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("puerto inválido %q: debe estar entre 1 y 65535", s)
	}
	return n, nil
}

// Address valida una dirección IP (v4 o v6) o un nombre DNS.
func Address(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return errors.New("la dirección no puede estar vacía")
	}
	if net.ParseIP(s) != nil {
		return nil
	}
	if len(s) > 253 {
		return errors.New("el nombre DNS es demasiado largo")
	}
	for _, label := range strings.Split(s, ".") {
		if !reLabel.MatchString(label) {
			return fmt.Errorf("dirección inválida %q: use una IP o un nombre DNS en minúsculas", s)
		}
	}
	return nil
}

// UnitName valida el nombre de una unidad de systemd. Si no trae un sufijo
// conocido (.service, .timer, .socket) se le agrega ".service".
func UnitName(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !reUnit.MatchString(s) {
		return "", fmt.Errorf("nombre de unidad inválido %q", s)
	}
	for _, suffix := range []string{".service", ".timer", ".socket"} {
		if strings.HasSuffix(s, suffix) {
			return s, nil
		}
	}
	return s + ".service", nil
}

// ServerName valida el nombre de un servidor en el backend de HAProxy.
func ServerName(s string) error {
	if !reServer.MatchString(s) {
		return fmt.Errorf("nombre de servidor inválido %q: use letras, dígitos, _ - . (máx. 32)", s)
	}
	return nil
}

// IssueText valida el mensaje personalizado de /etc/issue. Se rechazan la
// barra invertida (en /etc/issue introduce secuencias de escape que la
// interfaz ofrece con casillas) y los caracteres de control.
func IssueText(s string) (string, error) {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > 200 {
		return "", errors.New("el mensaje no puede superar los 200 caracteres")
	}
	for _, r := range s {
		if r == '\\' {
			return "", errors.New("no use la barra invertida; para mostrar nombre de host, fecha, hora o IP use las casillas")
		}
		if unicode.IsControl(r) {
			return "", errors.New("el mensaje debe ser una sola línea de texto sin caracteres de control")
		}
	}
	return s, nil
}
