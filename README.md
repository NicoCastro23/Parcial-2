# NP2 · Consola de automatización de servicios (Debian + VirtualBox)

Aplicación web en Go que automatiza tareas de administración sobre máquinas
virtuales Debian 13 en VirtualBox (Nota Parcial #2, Computación en la Nube).
Corre en el equipo anfitrión (tu Mac) y administra las VMs de forma no
interactiva.

## Estado de los módulos

| Punto del enunciado | Módulo | Estado |
|---|---|---|
| 3 (canales) | Guest Additions antes de SSH · SSH con llaves después | Núcleo hecho. SSH **probado contra un sshd real**; Guest Additions **sin probar con VirtualBox real** (ver "Pendiente de verificar") |
| 3.1.2 | Llave SSH de root (crear, autorizar, sin contraseña, descargar) | **Hecho y probado** |
| 3.1.1 | Instalar / eliminar aplicaciones | **Hecho** (pruebas unitarias; falta probar en la VM) |
| 3.1.3 | Pantalla de entrada `/etc/issue` | **Hecho** (pruebas unitarias y con `agetty` real; falta probar en la VM) |
| 3.1.4 | Nombre de host y `/etc/hosts` | **Hecho** (pruebas unitarias; falta probar en la VM) |
| 3.2.1 / 3.2.2 | Crear / eliminar usuarios | **Hecho** (pruebas unitarias; falta probar en la VM) |
| 3.3 | Servicios systemd | **Hecho** (pruebas unitarias; unidad validada con `systemd-analyze`; falta probar en la VM) |
| 3.4 | HAProxy: agregar / quitar servidor del backend | Pendiente |

## Ejecutar

Requisitos en el Mac: `ssh` y `ssh-keygen` (ya vienen con macOS) y VirtualBox
(`VBoxManage`) solo si usas Guest Additions.

```bash
# Opción A: binario ya compilado (Mac Intel)
chmod +x dist/np2auto-darwin-amd64
xattr -d com.apple.quarantine dist/np2auto-darwin-amd64   # si macOS lo bloquea
./dist/np2auto-darwin-amd64            # la 1.ª vez crea config.json y termina

# Opción B: compilar (necesita Go 1.24+)
go build -o np2auto . && ./np2auto
```

1. La primera ejecución crea `config.json` con valores de ejemplo y termina.
2. Edítalo: IP de cada VM, `vm_name` (nombre en VirtualBox), rutas de llaves.
3. Vuelve a ejecutar y abre <http://127.0.0.1:8088>.

### config.json

| Campo | Significado |
|---|---|
| `listen` | Dirección del servidor web. Por defecto solo `127.0.0.1`. |
| `data_dir` | Carpeta de datos: llaves generadas, `known_hosts` y registro. |
| `targets[].transport` | `guest` (antes de SSH) o `ssh` (con llave). El módulo de la llave de root lo cambia a `ssh` solo. |
| `targets[].user`, `key` | Usuario y llave privada para SSH. |
| `targets[].vm_name`, `guest_user` | VM y usuario para Guest Additions. |
| `targets[].guest_password_env` | **Nombre** de la variable de entorno con la contraseña del usuario invitado (nunca se guarda en el archivo). |

Ejemplo con Guest Additions y un usuario no root:

```bash
export NP2_GUEST_PASSWORD_TEST='la-contraseña-de-miguel'
./np2auto
```

## Cómo está hecha

```
main.go                      arranque
internal/config              config.json (guardado atómico, permisos 0600)
internal/validate            listas blancas para toda entrada del usuario (con pruebas de inyección)
internal/runner              Runner: SSH (llaves) y Guest (VBoxManage guestcontrol) + registro JSONL
internal/ops                 operaciones de automatización (llave SSH de root, paquetes, /etc/issue, nombre de host, usuarios, systemd)
internal/web                 servidor, plantillas y estilos (embebidos en el binario)
```

Decisiones de diseño (útiles para la documentación):

- **Un solo contrato para los dos canales.** Los módulos reciben un `Runner` y
  no saben si hablan por Guest Additions o por SSH. Cambiar de canal es cambiar
  un campo.
- **SSH con el cliente `ssh` del sistema**, no con una biblioteca: cero
  dependencias externas y el mismo comportamiento que se prueba a mano en la
  terminal. Siempre `BatchMode` (nunca pregunta contraseñas) y
  `StrictHostKeyChecking=accept-new` con un `known_hosts` propio.
- **El script viaja en base64 como argumento** (`bash -c "$(printf %s … | base64 -d)"`):
  sin problemas de comillas y con la entrada estándar libre, para que un
  comando como `apt` no se "coma" el resto del script.
- **Dos barreras contra inyección de comandos:** validación con listas blancas
  (`internal/validate`) y escape de todo valor incrustado (`runner.Quote`).
- **Endurecer SSH sin bloquearse.** La llave se prueba *antes* de deshabilitar
  la contraseña; se comprueba la configuración *efectiva* (`sshd -T`); se
  vuelve a probar la llave *después*; si algo falla se revierte solo. El
  cambio vive en un archivo propio, `/etc/ssh/sshd_config.d/00-np2-hardening.conf`,
  que se lee antes que `sshd_config`, no se edita el archivo principal.
- **Rotación de llaves sin cortar el acceso:** la llave nueva se genera en una
  ruta provisional y solo reemplaza a la anterior (que queda como `.old-…`)
  cuando todo salió bien. Si la operación falla, se retira la llave nueva de la VM.
- **Las operaciones no se cancelan si el navegador se desconecta** (tienen su
  propio límite de tiempo): una operación a medias es más peligrosa que una
  que termina sola. Solo una operación a la vez por VM.
- **Protección de la propia consola** (ejecuta comandos como root): escucha en
  `127.0.0.1`, rechaza `Host` ajenos (DNS rebinding) y exige token CSRF en todo POST.
- **Paquetes (3.1.1):** `apt-get` no interactivo (`DEBIAN_FRONTEND=noninteractive`,
  `--force-confold`, espera el bloqueo de apt hasta 3 min). Antes de instalar se
  comprueba que el paquete exista (mensaje claro en vez del error de apt). Antes
  de eliminar se **simula** (`apt-get -s`) y se cancela si la eliminación
  arrastraría paquetes necesarios para administrar la VM (SSH, sudo, red,
  arranque): por ejemplo, quitar `openssh-client` arrastra `openssh-server`.
  Al final se comprueba con `dpkg-query` que el estado sea el pedido.
- **Pantalla de entrada (3.1.3):** cada casilla agrega una secuencia de escape
  de `agetty` (`\n` nombre de host, `\d` fecha, `\t` hora, `\4` IP, `\S`
  sistema...), así los valores son siempre los actuales. El mensaje no admite
  `\` para que no se puedan colar secuencias de escape. Tras escribir se
  comprueba el contenido exacto y se muestra cómo queda en la consola
  (`agetty --show-issue` dentro de `script`, que le da la terminal que
  necesita); `agetty --reload` actualiza las consolas abiertas. Copias:
  `/etc/issue.np2-prev` y `/etc/issue.np2-orig` (botón "Restaurar el original").
- **Usuarios (3.2):** `useradd -m -U -s /bin/bash`. Con la casilla de llaves,
  el par se genera en este equipo (la privada no viaja a la VM), la pública
  va a `~usuario/.ssh/authorized_keys` y la contraseña queda **bloqueada**
  (`passwd -l`): así el usuario no puede entrar con login y contraseña ni por
  SSH ni en consola. Como no tiene contraseña, si además tiene sudo se le da
  `NOPASSWD` en `/etc/sudoers.d/np2-<usuario>` (validado con `visudo -cf`).
  Al final se inicia sesión por SSH **como el usuario nuevo** con su llave
  (y se prueba `sudo -n`). Sin llaves se pide contraseña (`chpasswd`), que se
  oculta en el registro de operaciones. Si algo falla a mitad de camino, el
  usuario se elimina para no dejarlo a medio configurar. Al eliminar se
  protegen las cuentas del sistema (UID < 1000) y el usuario con el que la
  aplicación se conecta; se terminan sus procesos antes de `userdel [-r]`.
- **Servicios systemd (3.3):** los archivos se toman de una ruta en el equipo
  donde corre la consola (carpeta o archivo; sin límite del navegador y
  conservando la estructura de carpetas) y viajan como `tar.gz` por la
  entrada estándar de la misma conexión SSH, sin archivos temporales. Antes de
  transferir se revisa que el ejecutable sea ELF o un script con `#!` (un
  binario de macOS daría "Exec format error" en la VM). En la VM: usuario de
  sistema `svc-<nombre>` sin shell ni contraseña, `/opt/<nombre>` de su
  propiedad y sin acceso para otros, unidad con `User=`, `WorkingDirectory=`,
  `Restart=on-failure` (tipo simple) y `NoNewPrivileges=yes`, marcada como
  creada por la aplicación: solo esas se actualizan o desinstalan. Tipo
  `oneshot` para scripts que terminan (el de fecha y hora). Los botones
  start/stop/restart/status/enable/disable funcionan sobre cualquier unidad,
  comprueban el estado resultante y muestran `systemctl status`; no se
  permite detener ni deshabilitar `ssh`, la red ni servicios básicos.
- **Nombre de host (3.1.4):** `hostnamectl set-hostname` (con respaldo manual
  en `/etc/hostname` si no está disponible) y una sola línea `127.0.1.1` en
  `/etc/hosts`, que es la convención de Debian. Se guarda `/etc/hosts.np2-prev`
  y la pantalla muestra el estado antes y después, útil para los videos.
- **Registro de operaciones** (`data/logs/operaciones.jsonl`, también en la
  pantalla "Registro"): qué se ejecutó, dónde, qué respondió y cuánto tardó.
  Es la información técnica para diagnóstico y para las evidencias de prueba.

## Pruebas

```bash
go vet ./... && go test ./...          # unitarias: validación, runners, config, web
```

Prueba de integración contra un `sshd` real (modifica `/etc/ssh/sshd_config.d/`
del equipo donde corre: usar solo en un entorno desechable). Necesita un sshd
de prueba como root en el puerto 2222 con una llave de arranque autorizada, y
un `systemctl` en el `PATH` que recargue ese sshd:

```bash
NP2_IT_PORT=2222 NP2_IT_KEY=/ruta/llave_de_arranque \
  go test -tags integration -count=1 -v ./internal/ops/
```

Cubren: operación completa (9 pasos), comprobación de que el servidor pasa de
ofrecer `publickey,password` a solo `publickey`, rotación de llave, y la
detención segura cuando la llave nueva no permite entrar.

## Pendiente de verificar (honestidad sobre el alcance)

- **Guest Additions no se ha probado con VirtualBox real.** Solo está probada
  la construcción de argumentos y la clasificación de errores con un
  `VBoxManage` falso. Antes de depender de él: `VBoxManage guestcontrol mv1 run --help`
  para confirmar las opciones (`--exe`, `--passwordfile`, `--wait-stdout`,
  `--timeout`), y comprobar que la VM tiene las Guest Additions instaladas y
  en ejecución (`systemctl status virtualbox-guest-utils`). Si el `.ova`
  `debian-cli` no las trae, ese canal no funcionará hasta instalarlas.
- **No se ha ejecutado contra tu Debian 13 real**, solo contra un sshd de
  Ubuntu 24.04. El unit de systemd de Debian se llama `ssh` (el código
  también intenta `sshd`).
- El binario de macOS está compilado pero **no se pudo ejecutar** en el entorno
  donde se construyó; el mismo código sí corre en Linux.
- Las llaves anteriores **siguen autorizadas en la VM** tras rotar; borrarlas
  de `/root/.ssh/authorized_keys` es manual (la pantalla lo advierte).
