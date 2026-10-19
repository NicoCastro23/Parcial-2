// Comando np2auto: consola web (Go) para automatizar tareas de administración
// de máquinas virtuales Debian en VirtualBox. Ver README.md.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"np2auto/internal/config"
	"np2auto/internal/web"
)

func main() {
	cfgPath := flag.String("config", "config.json", "ruta del archivo de configuración")
	flag.Parse()

	store, created, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("configuración: %v", err)
	}
	if created {
		fmt.Printf("Se creó %s con valores de ejemplo. Edítelo (IP, nombres de VM, rutas de llaves) y vuelva a ejecutar.\n", *cfgPath)
		os.Exit(0)
	}

	srv, err := web.New(store)
	if err != nil {
		log.Fatalf("servidor: %v", err)
	}
	listen := store.Snapshot().Listen
	httpSrv := &http.Server{
		Addr:              listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// Sin WriteTimeout: las operaciones (p. ej. apt) pueden tardar minutos
		// y cada una tiene su propio límite de tiempo.
		IdleTimeout: 2 * time.Minute,
	}
	log.Printf("NP2 escuchando en http://%s", listen)
	log.Fatal(httpSrv.ListenAndServe())
}
