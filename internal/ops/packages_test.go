package ops

import (
	"context"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func TestManagePackagesInstall(t *testing.T) {
	f := &fakeRunner{stdout: map[string]string{
		"paquetes/antes":     "htop\tno-instalado\t\ntree\tinstalado\t2.1.1-2\n",
		"paquetes/instalar":  "Reading package lists...\n1 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.\n",
		"paquetes/verificar": "htop\tinstalado\t3.4.1-4\ntree\tinstalado\t2.1.1-2\n",
	}}
	res := ManagePackages(context.Background(), f, PackagesInput{Action: PkgInstall, Packages: []string{"htop", "tree"}})
	if !res.OK {
		t.Fatalf("debería terminar bien: %+v", res.Steps)
	}
	want := "paquetes/antes,paquetes/update,paquetes/existe,paquetes/instalar,paquetes/verificar"
	if got := strings.Join(f.ops, ","); got != want {
		t.Errorf("pasos %s; quería %s", got, want)
	}
	if !strings.Contains(f.scripts[3], "apt-get install -y") || !strings.Contains(f.scripts[3], "-- 'htop' 'tree'") {
		t.Errorf("comando de instalación inesperado: %s", f.scripts[3])
	}
	last := res.Steps[len(res.Steps)-1].Detail
	if !strings.Contains(last, "htop: no instalado") || !strings.Contains(last, "htop: instalado (3.4.1-4)") {
		t.Errorf("el resumen debe mostrar antes y después: %q", last)
	}
}

func TestManagePackagesInstallUnknown(t *testing.T) {
	f := &fakeRunner{stdout: map[string]string{
		"paquetes/antes":  "noexiste\tno-instalado\t\n",
		"paquetes/existe": "noexiste\n",
	}}
	res := ManagePackages(context.Background(), f, PackagesInput{Action: PkgInstall, Packages: []string{"noexiste"}})
	s := res.Steps[len(res.Steps)-1]
	if res.OK || !strings.Contains(s.Detail, "no se encontró en los repositorios configurados: noexiste") {
		t.Fatalf("debe explicar que el paquete no existe: %+v", s)
	}
	for _, op := range f.ops {
		if op == "paquetes/instalar" {
			t.Error("no debe intentar instalar")
		}
	}
}

func TestManagePackagesRemove(t *testing.T) {
	f := &fakeRunner{stdout: map[string]string{
		"paquetes/antes":     "htop\tinstalado\t3.4.1-4\ntree\tno-instalado\t\n",
		"paquetes/simular":   "Remv htop [3.4.1-4]\n",
		"paquetes/verificar": "htop\tconfiguracion-residual\t\ntree\tno-instalado\t\n",
	}}
	res := ManagePackages(context.Background(), f, PackagesInput{Action: PkgRemove, Packages: []string{"htop", "tree"}})
	if !res.OK {
		t.Fatalf("debería terminar bien: %+v", res.Steps)
	}
	// Solo se elimina el que está instalado.
	if !strings.Contains(f.scripts[2], "apt-get remove -y") || !strings.HasSuffix(strings.TrimSpace(f.scripts[2]), "-- 'htop'") {
		t.Errorf("comando de eliminación inesperado: %s", f.scripts[2])
	}
	if d := res.Steps[1].Detail; !strings.Contains(d, "Se eliminará: htop") || !strings.Contains(d, "No estaban instalados: tree") {
		t.Errorf("la simulación debe informar qué se elimina: %q", d)
	}
}

func TestManagePackagesPurgeLeavesNoConfig(t *testing.T) {
	f := &fakeRunner{stdout: map[string]string{
		"paquetes/antes":     "htop\tinstalado\t3.4.1-4\n",
		"paquetes/simular":   "Purg htop [3.4.1-4]\n",
		"paquetes/verificar": "htop\tconfiguracion-residual\t\n",
	}}
	res := ManagePackages(context.Background(), f, PackagesInput{Action: PkgRemove, Packages: []string{"htop"}, Purge: true})
	if res.OK {
		t.Fatal("con purga, si quedan archivos de configuración debe informar el fallo")
	}
	if !strings.Contains(f.scripts[1], "apt-get -s purge") {
		t.Errorf("debía simular purge: %s", f.scripts[1])
	}
}

func TestManagePackagesBlocksProtected(t *testing.T) {
	// Quitar openssh-client arrastra openssh-server: cortaría el canal SSH.
	f := &fakeRunner{stdout: map[string]string{
		"paquetes/antes":   "openssh-client\tinstalado\t1:10.0p1-7\n",
		"paquetes/simular": "Remv openssh-server [1:10.0p1-7]\nRemv openssh-client [1:10.0p1-7]\n",
	}}
	res := ManagePackages(context.Background(), f, PackagesInput{Action: PkgRemove, Packages: []string{"openssh-client"}})
	s := res.Steps[len(res.Steps)-1]
	if res.OK || !strings.Contains(s.Detail, "openssh-client, openssh-server") {
		t.Fatalf("debe cancelar y nombrar los paquetes protegidos: %+v", s)
	}
	for _, op := range f.ops {
		if op == "paquetes/eliminar" {
			t.Error("no debe ejecutar la eliminación")
		}
	}
}

func TestManagePackagesRemoveNothingInstalled(t *testing.T) {
	f := &fakeRunner{stdout: map[string]string{"paquetes/antes": "htop\tno-instalado\t\n"}}
	res := ManagePackages(context.Background(), f, PackagesInput{Action: PkgRemove, Packages: []string{"htop"}})
	if !res.OK || len(f.ops) != 1 || !strings.Contains(res.Steps[1].Detail, "no hay nada que eliminar") {
		t.Fatalf("debe terminar sin tocar apt: ok=%v ops=%v", res.OK, f.ops)
	}
}

func TestManagePackagesRejectsInvalidInput(t *testing.T) {
	for _, in := range []PackagesInput{
		{Action: PkgInstall, Packages: []string{"vim; reboot"}},
		{Action: PkgInstall},
		{Action: "upgrade", Packages: []string{"vim"}},
		{Action: PkgInstall, Packages: []string{"-oAPT::x=1"}},
	} {
		f := &fakeRunner{}
		if res := ManagePackages(context.Background(), f, in); res.OK || len(f.ops) != 0 {
			t.Errorf("%+v: no debe ejecutar nada en la VM", in)
		}
	}
}

func TestParseSimulatedRemovals(t *testing.T) {
	out := "Reading package lists...\nThe following packages will be REMOVED:\n  htop tree\nRemv tree [2.1.1-2]\nPurg htop [3.4.1-4]\n"
	if got := parseSimulatedRemovals(out); !reflect.DeepEqual(got, []string{"htop", "tree"}) {
		t.Errorf("got %v", got)
	}
}

func TestIsProtected(t *testing.T) {
	for _, p := range []string{"openssh-server", "sudo", "linux-image-amd64", "grub-pc", "virtualbox-guest-utils"} {
		if !isProtected(p) {
			t.Errorf("%s debería estar protegido", p)
		}
	}
	for _, p := range []string{"htop", "haproxy", "apache2", "nginx"} {
		if isProtected(p) {
			t.Errorf("%s no debería estar protegido", p)
		}
	}
}

// TestPkgStateScript ejecuta la consulta real con dpkg-query (solo lectura).
func TestPkgStateScript(t *testing.T) {
	if _, err := exec.LookPath("dpkg-query"); err != nil {
		t.Skip("dpkg-query no disponible")
	}
	out, err := exec.Command("bash", "-c", "set -eu\n"+pkgStateScript([]string{"bash", "paquete-que-no-existe-np2"})).CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	m := parsePkgStates(string(out))
	if !m["bash"].installed() || m["bash"].Version == "" {
		t.Errorf("bash debería figurar instalado con versión: %+v (%s)", m["bash"], out)
	}
	if m["paquete-que-no-existe-np2"].State != "no-instalado" {
		t.Errorf("paquete inexistente: %+v", m["paquete-que-no-existe-np2"])
	}
}
