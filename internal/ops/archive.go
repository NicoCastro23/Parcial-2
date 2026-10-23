package ops

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// maxUpload limita lo que se transfiere a la VM en una operación.
const maxUpload = 1 << 30 // 1 GiB

// bundle describe los archivos que se van a transferir.
type bundle struct {
	root  string   // carpeta (o archivo) de origen
	files []string // rutas relativas de los archivos regulares
	dirs  []string // rutas relativas de las carpetas
	size  int64
}

// skipNames son archivos de sistema o de control de versiones que no tiene
// sentido llevar a la VM.
var skipNames = map[string]bool{".git": true, ".DS_Store": true, "__MACOSX": true}

// scanBundle recorre el origen (un archivo o una carpeta) y valida que se
// pueda transferir: solo archivos y carpetas normales, sin pasar el límite.
func scanBundle(src string) (*bundle, error) {
	info, err := os.Stat(src)
	if err != nil {
		return nil, fmt.Errorf("no se encuentra %s en este equipo", src)
	}
	if !info.IsDir() {
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%s no es un archivo normal", src)
		}
		return &bundle{root: filepath.Dir(src), files: []string{filepath.Base(src)}, size: info.Size()}, checkSize(info.Size())
	}
	b := &bundle{root: src}
	err = filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == src {
			return nil
		}
		if skipNames[d.Name()] {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(src, p)
		rel = filepath.ToSlash(rel)
		switch {
		case d.IsDir():
			b.dirs = append(b.dirs, rel)
		case d.Type().IsRegular():
			fi, err := d.Info()
			if err != nil {
				return err
			}
			b.files = append(b.files, rel)
			b.size += fi.Size()
		case d.Type()&fs.ModeSymlink != 0:
			return fmt.Errorf("%s es un enlace simbólico: copie el archivo real en su lugar", rel)
		default:
			return fmt.Errorf("%s no es un archivo normal", rel)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(b.files) == 0 {
		return nil, fmt.Errorf("la carpeta %s no tiene archivos", src)
	}
	return b, checkSize(b.size)
}

func checkSize(n int64) error {
	if n > maxUpload {
		return fmt.Errorf("los archivos ocupan %s; el máximo por operación es %s", humanSize(n), humanSize(maxUpload))
	}
	return nil
}

func (b *bundle) has(rel string) bool {
	for _, f := range b.files {
		if f == rel {
			return true
		}
	}
	return false
}

// stream devuelve un lector con el tar.gz del contenido. Se genera mientras
// se envía, sin archivos temporales. Los permisos se conservan solo para el
// dueño y el grupo (los ajusta luego la operación en la VM).
func (b *bundle) stream() io.ReadCloser {
	pr, pw := io.Pipe()
	go func() {
		gz := gzip.NewWriter(pw)
		tw := tar.NewWriter(gz)
		err := func() error {
			for _, d := range b.dirs {
				if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: d + "/", Mode: 0o750}); err != nil {
					return err
				}
			}
			for _, rel := range b.files {
				if err := addFile(tw, filepath.Join(b.root, filepath.FromSlash(rel)), rel); err != nil {
					return err
				}
			}
			if err := tw.Close(); err != nil {
				return err
			}
			return gz.Close()
		}()
		pw.CloseWithError(err)
	}()
	return pr
}

func addFile(tw *tar.Writer, path, rel string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	mode := int64(0o640)
	if fi.Mode()&0o100 != 0 {
		mode = 0o750 // ejecutable para el dueño: se conserva
	}
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: rel, Mode: mode, Size: fi.Size(), ModTime: fi.ModTime()}); err != nil {
		return err
	}
	n, err := io.Copy(tw, f)
	if err == nil && n != fi.Size() {
		err = errors.New(rel + " cambió de tamaño mientras se transfería")
	}
	return err
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// summary describe el contenido para el usuario.
func (b *bundle) summary() string {
	names := b.files
	more := ""
	if len(names) > 6 {
		names, more = names[:6], fmt.Sprintf(" y %d más", len(b.files)-6)
	}
	return fmt.Sprintf("%d archivos (%s): %s%s", len(b.files), humanSize(b.size), strings.Join(names, ", "), more)
}
