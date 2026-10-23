package ops

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"np2auto/internal/runner"
)

// appDir crea una carpeta de aplicación de prueba como la del catálogo.
func appDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	write := func(rel, content string, mode os.FileMode) {
		p := filepath.Join(d, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("catalogo", "\x7fELF-binario-falso", 0o755)
	write("templates/index.html", "<h1>Libros</h1>", 0o644)
	write("static/style.css", "body{}", 0o644)
	write(".git/config", "no-debe-viajar", 0o644)
	write(".DS_Store", "x", 0o644)
	return d
}

func untar(t *testing.T, data []byte) map[string]int64 {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	got := map[string]int64{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got[h.Name] = h.Mode
	}
	return got
}

func TestBundle(t *testing.T) {
	d := appDir(t)
	b, err := scanBundle(d)
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(b.files)
	if strings.Join(b.files, ",") != "catalogo,static/style.css,templates/index.html" {
		t.Errorf("archivos: %v (no deben ir .git ni .DS_Store)", b.files)
	}
	rc := b.stream()
	data, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatal(err)
	}
	got := untar(t, data)
	if got["catalogo"] != 0o750 || got["templates/index.html"] != 0o640 || got["templates/"] != 0o750 {
		t.Errorf("permisos en el tar: %v", got)
	}
	// Se puede extraer con el tar del sistema, como lo hará la VM.
	if _, err := exec.LookPath("tar"); err == nil {
		out := t.TempDir()
		cmd := exec.Command("tar", "-xzf", "-", "--no-same-owner", "-C", out)
		cmd.Stdin = bytes.NewReader(data)
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("tar: %v %s", err, b)
		}
		if c, _ := os.ReadFile(filepath.Join(out, "templates/index.html")); string(c) != "<h1>Libros</h1>" {
			t.Errorf("contenido extraído: %q", c)
		}
	}
}

func TestBundleRejects(t *testing.T) {
	d := t.TempDir()
	if _, err := scanBundle(d); err == nil || !strings.Contains(err.Error(), "no tiene archivos") {
		t.Errorf("carpeta vacía: %v", err)
	}
	os.WriteFile(filepath.Join(d, "app"), []byte("#!/bin/sh"), 0o755)
	os.Symlink("/etc/passwd", filepath.Join(d, "enlace"))
	if _, err := scanBundle(d); err == nil || !strings.Contains(err.Error(), "enlace simbólico") {
		t.Errorf("enlace simbólico: %v", err)
	}
	if _, err := scanBundle("/no/existe"); err == nil {
		t.Error("ruta inexistente debe fallar")
	}
	// Un solo archivo.
	f := filepath.Join(t.TempDir(), "fecha.sh")
	os.WriteFile(f, []byte("#!/bin/bash\ndate >> registro.txt\n"), 0o644)
	b, err := scanBundle(f)
	if err != nil || len(b.files) != 1 || b.files[0] != "fecha.sh" {
		t.Errorf("archivo único: %+v %v", b, err)
	}
}

func TestCheckExecutable(t *testing.T) {
	cases := map[string]string{
		"\x7fELF...":          "",
		"#!/bin/bash\n":       "",
		"\xcf\xfa\xed\xfe...": "macOS",
		"MZ\x90\x00":          "Windows",
		"echo hola":           "#!",
	}
	for content, wantErr := range cases {
		p := filepath.Join(t.TempDir(), "x")
		os.WriteFile(p, []byte(content), 0o755)
		_, err := checkExecutable(p)
		switch {
		case wantErr == "" && err != nil:
			t.Errorf("%q: %v", content, err)
		case wantErr != "" && (err == nil || !strings.Contains(err.Error(), wantErr)):
			t.Errorf("%q: quería error con %q, obtuvo %v", content, wantErr, err)
		}
	}
}

func TestUnitFile(t *testing.T) {
	in := ServiceInput{Name: "catalogo", Exec: "catalogo", Args: []string{"-port", "8080"}, Env: []string{"GIN_MODE=release"}, Type: SvcSimple, LowPorts: true}
	want := managedMarker + `
[Unit]
Description=catalogo (desplegado por NP2)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=svc-catalogo
Group=svc-catalogo
WorkingDirectory=/opt/catalogo
ExecStart=/opt/catalogo/catalogo -port 8080
Environment=GIN_MODE=release
Restart=on-failure
RestartSec=3
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
`
	if got := in.UnitFile(); got != want {
		t.Errorf("unidad:\n%s\nquería:\n%s", got, want)
	}
	one := ServiceInput{Name: "fecha", Exec: "fecha.sh", Type: SvcOneshot}.UnitFile()
	if strings.Contains(one, "Restart=") || !strings.Contains(one, "Type=oneshot") {
		t.Errorf("oneshot no debe reiniciarse:\n%s", one)
	}
}

func TestDeployServiceFlow(t *testing.T) {
	f := &fakeRunner{stdout: map[string]string{
		"servicios/estado": "activo=active\nhabilitado=enabled\ntipo=simple\nresultado=success\n---\n● catalogo.service - catalogo\n     Active: active (running)\n",
	}}
	in := ServiceInput{Name: "catalogo", Source: appDir(t), Exec: "catalogo", Type: SvcSimple, Start: true}
	res := DeployService(context.Background(), f, in)
	if !res.OK {
		t.Fatalf("debería terminar bien: %+v", res.Steps)
	}
	want := "servicios/comprobar,servicios/usuario,servicios/transferir,servicios/instalar,servicios/unidad,servicios/iniciar,servicios/estado"
	if got := strings.Join(f.ops, ","); got != want {
		t.Errorf("pasos %s; quería %s", got, want)
	}
	if got := untar(t, f.upload); len(got) != 5 { // 2 carpetas + 3 archivos
		t.Errorf("transferido: %v", got)
	}
	if !strings.Contains(f.scripts[4], "ExecStart=/opt/catalogo/catalogo") || !strings.Contains(f.scripts[4], "daemon-reload") {
		t.Errorf("script de la unidad: %s", f.scripts[4])
	}
	if !strings.Contains(res.Preview, "Active: active (running)") {
		t.Errorf("vista previa: %q", res.Preview)
	}
}

func TestDeployServiceDetectsFailedStart(t *testing.T) {
	f := &fakeRunner{stdout: map[string]string{
		"servicios/estado": "activo=activating\nhabilitado=enabled\ntipo=simple\nresultado=exit-code\n---\nMain PID: 123 (code=exited, status=1/FAILURE)\n",
	}}
	res := DeployService(context.Background(), f, ServiceInput{Name: "catalogo", Source: appDir(t), Exec: "catalogo", Type: SvcSimple, Start: true})
	last := res.Steps[len(res.Steps)-1]
	if res.OK || !strings.Contains(last.Detail, `quedó "activating"`) || !strings.Contains(res.Preview, "status=1/FAILURE") {
		t.Fatalf("debe informar que no quedó activo y mostrar el estado: %+v %q", last, res.Preview)
	}
}

func TestDeployServiceSingleScript(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fecha.sh")
	os.WriteFile(p, []byte("#!/bin/bash\necho \"$(date)\" >> /opt/fecha/registro.txt\n"), 0o644)
	f := &fakeRunner{stdout: map[string]string{"servicios/estado": "activo=inactive\nhabilitado=enabled\ntipo=oneshot\nresultado=success\n---\n"}}
	res := DeployService(context.Background(), f, ServiceInput{Name: "fecha", Source: p, Type: SvcOneshot, Start: true})
	if !res.OK {
		t.Fatalf("un oneshot que terminó bien es correcto: %+v", res.Steps)
	}
	if !strings.Contains(f.scripts[3], "exe='fecha.sh'") {
		t.Errorf("el ejecutable debe ser el archivo: %s", f.scripts[3])
	}
}

// soloRun es un canal sin transferencia (como Guest Additions).
type soloRun struct{ f *fakeRunner }

func (s soloRun) Transport() string { return "guest" }
func (s soloRun) Describe() string  { return "guest" }
func (s soloRun) Run(ctx context.Context, sc string) (runner.Result, error) {
	return s.f.Run(ctx, sc)
}

func TestDeployServiceRequiresSSH(t *testing.T) {
	f := &fakeRunner{}
	res := DeployService(context.Background(), soloRun{f}, ServiceInput{Name: "catalogo", Source: appDir(t), Exec: "catalogo", Type: SvcSimple})
	if res.OK || !strings.Contains(res.Steps[len(res.Steps)-1].Detail, "requiere el canal SSH") {
		t.Fatalf("%+v", res.Steps)
	}
}

func TestDeployServiceValidation(t *testing.T) {
	d := appDir(t)
	mac := filepath.Join(t.TempDir(), "app")
	os.WriteFile(mac, []byte("\xcf\xfa\xed\xfe"), 0o755)
	for _, c := range []struct {
		in   ServiceInput
		want string
	}{
		{ServiceInput{Name: "ssh.service", Source: d, Exec: "catalogo", Type: SvcSimple}, "nombre de servicio inválido"},
		{ServiceInput{Name: "catalogo", Source: "relativa/app", Exec: "catalogo", Type: SvcSimple}, "ruta completa"},
		{ServiceInput{Name: "catalogo", Source: d, Exec: "../etc/passwd", Type: SvcSimple}, "no use . ni .."},
		{ServiceInput{Name: "catalogo", Source: d, Exec: "noexiste", Type: SvcSimple}, "no se encontró el ejecutable"},
		{ServiceInput{Name: "catalogo", Source: d, Type: SvcSimple}, "indique cuál es el ejecutable"},
		{ServiceInput{Name: "catalogo", Source: mac, Type: SvcSimple}, "binario de macOS"},
		{ServiceInput{Name: "catalogo", Source: d, Exec: "catalogo", Type: "forking"}, "tipo de servicio inválido"},
	} {
		f := &fakeRunner{}
		res := DeployService(context.Background(), f, c.in)
		if res.OK || len(f.ops) != 0 || !strings.Contains(res.Steps[len(res.Steps)-1].Detail, c.want) {
			t.Errorf("%+v: quería %q sin tocar la VM; pasos %+v, ops %v", c.in, c.want, res.Steps, f.ops)
		}
	}
}

func TestUnitAction(t *testing.T) {
	f := &fakeRunner{stdout: map[string]string{"servicios/estado": "activo=inactive\nhabilitado=disabled\ntipo=simple\nresultado=success\n---\n○ catalogo.service\n"}}
	res := UnitAction(context.Background(), f, "catalogo", "stop")
	if !res.OK || strings.Join(f.ops, ",") != "servicios/stop,servicios/estado" || !strings.Contains(f.scripts[0], `systemctl stop "$u"`) {
		t.Fatalf("stop: %+v %v", res.Steps, f.ops)
	}
	if !strings.Contains(f.scripts[0], "u='catalogo.service'") {
		t.Errorf("debe completar el sufijo .service: %s", f.scripts[0])
	}
	// start de un simple que queda inactivo: fallo.
	if res := UnitAction(context.Background(), f, "catalogo", "start"); res.OK {
		t.Error("start que deja el servicio inactivo debe fallar")
	}
	// enable que no queda enabled: fallo.
	if res := UnitAction(context.Background(), f, "catalogo", "enable"); res.OK {
		t.Error("enable que no queda habilitado debe fallar")
	}
	// status no ejecuta acciones.
	f.ops = nil
	if res := UnitAction(context.Background(), f, "catalogo.service", "status"); !res.OK || len(f.ops) != 1 {
		t.Errorf("status: %v", f.ops)
	}
}

func TestUnitActionProtectsCriticalUnits(t *testing.T) {
	for _, c := range []struct{ unit, action string }{{"ssh", "stop"}, {"ssh.service", "disable"}, {"networking", "stop"}} {
		f := &fakeRunner{}
		if res := UnitAction(context.Background(), f, c.unit, c.action); res.OK || len(f.ops) != 0 {
			t.Errorf("%s %s debe rechazarse sin tocar la VM", c.action, c.unit)
		}
	}
	// Reiniciar ssh sí se permite (no corta las sesiones abiertas).
	f := &fakeRunner{stdout: map[string]string{"servicios/estado": "activo=active\ntipo=notify\n---\n"}}
	if res := UnitAction(context.Background(), f, "ssh", "restart"); !res.OK {
		t.Errorf("restart ssh: %+v", res.Steps)
	}
	for _, bad := range []string{"a;reboot", "$(id)", ""} {
		f := &fakeRunner{}
		if res := UnitAction(context.Background(), f, bad, "status"); res.OK || len(f.ops) != 0 {
			t.Errorf("unidad %q debe rechazarse", bad)
		}
	}
	if res := UnitAction(context.Background(), &fakeRunner{}, "catalogo", "mask"); res.OK {
		t.Error("acción desconocida debe rechazarse")
	}
}

func TestUndeployService(t *testing.T) {
	f := &fakeRunner{}
	res := UndeployService(context.Background(), f, "catalogo")
	if !res.OK || !strings.Contains(f.scripts[0], "rm -rf \"$dir\"") || !strings.Contains(f.scripts[0], managedMarker) {
		t.Fatalf("%+v", res.Steps)
	}
	if res := UndeployService(context.Background(), &fakeRunner{}, "../etc"); res.OK {
		t.Error("nombre inválido debe rechazarse")
	}
}
