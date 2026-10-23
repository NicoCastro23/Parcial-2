# Guía de pruebas paso a paso

Orden recomendado para probar toda la consola contra las VMs reales y grabar
los videos. Cada módulo tiene un botón para mostrar el **estado anterior**
antes de ejecutar y la pantalla muestra el **estado posterior** al terminar:
grabe los dos, como pide el enunciado.

Todo lo que la aplicación ejecuta queda en **Registro de operaciones**
(`data/logs/operaciones.jsonl`): úselo como evidencia y, si algo falla, copie
de ahí el detalle técnico.

---

## 0. Qué necesita

En el Mac (equipo anfitrión):

- **Go 1.24 o superior** (`go version`). Si no lo tiene: `brew install go`.
- **VirtualBox** con `VBoxManage` en el `PATH` (`VBoxManage --version`).
- `ssh` y `ssh-keygen` (vienen con macOS).

Las VMs (precondiciones del enunciado):

| VM | Para qué | Qué debe tener |
|---|---|---|
| **VM de pruebas** (p. ej. `mv1`) | Módulos 3.1, 3.2 y 3.3 | Debian 13, red en modo puente, SSH activo |
| **VM del balanceador** | Módulo 3.4 | Lo mismo + `haproxy` con su configuración por defecto |
| **1 o 2 VMs web** (del disco multiconexión) | Servidores del backend en 3.4 | Debian 13, red en modo puente |

Anote la IP de cada VM: en su consola, `ip -4 addr` (la de `enp0s3` o similar,
no la `127.0.0.1`). Compruebe desde el Mac que responden: `ping <IP>`.

Averigüe también la arquitectura de la VM de pruebas: `uname -m`
(`x86_64` → compilará para `amd64`; `aarch64` → `arm64`). La necesita en 3.3.

---

## 1. Preparar la consola

```bash
git clone https://github.com/nicocastro23/parcial-2.git
cd parcial-2
git checkout feature/3.4-haproxy      # o main, si ya se fusionó

go vet ./... && go test ./...         # todo debe decir "ok"
go build -o np2auto .
./np2auto                             # la 1.ª vez crea config.json y termina
```

Edite `config.json` con sus datos. Ejemplo:

```json
{
  "listen": "127.0.0.1:8088",
  "data_dir": "data",
  "vboxmanage": "VBoxManage",
  "targets": [
    {
      "id": "test", "label": "VM de pruebas",
      "host": "192.168.1.65", "port": 22, "user": "root", "key": "",
      "transport": "guest",
      "vm_name": "mv1", "guest_user": "root",
      "guest_password_env": "NP2_GUEST_PASSWORD_TEST"
    },
    {
      "id": "balancer", "label": "VM del balanceador (HAProxy)",
      "host": "192.168.1.68", "port": 22, "user": "root", "key": "",
      "transport": "guest",
      "vm_name": "balanceador", "guest_user": "root",
      "guest_password_env": "NP2_GUEST_PASSWORD_BALANCER"
    }
  ]
}
```

- `host`: la IP de la VM. `vm_name`: el nombre **exacto** de la VM en VirtualBox.
- `guest_user`: use **`root`**. En Debian, si al instalar puso contraseña de
  root, `sudo` no viene instalado y un usuario normal no puede elevar
  privilegios.
- La contraseña **no** va en el archivo: va en una variable de entorno.

Arranque la consola:

```bash
export NP2_GUEST_PASSWORD_TEST='contraseña-de-root-de-mv1'
export NP2_GUEST_PASSWORD_BALANCER='contraseña-de-root-del-balanceador'
./np2auto
```

Abra <http://127.0.0.1:8088>. Arriba a la derecha se elige la **VM destino**.

---

## 2. Conexión por Guest Additions

1. Encienda la VM de pruebas y espere a que arranque.
2. **Conexión con las VMs** → **Probar conexión**. Debe mostrar
   `usuario: root`, el nombre de host, el sistema y la IP.

Si falla, lea el mensaje:

- *"VM ... is not running"*: la VM está apagada o `vm_name` no coincide.
- *"guest execution service is not ready"* o similar: la VM no tiene las
  **Guest Additions** activas. En la VM: `systemctl status vboxadd-service`.
  Para instalarlas: menú de la ventana de la VM → *Dispositivos → Insertar
  imagen de CD de las Guest Additions*, y en la VM como root:
  ```bash
  apt install -y build-essential linux-headers-$(uname -r)
  mount /dev/cdrom /mnt && sh /mnt/VBoxLinuxAdditions.run && reboot
  ```
- *"authentication failure"*: la contraseña de la variable de entorno no es
  la de `guest_user`. Corrija el `export` y reinicie `./np2auto`.

**Plan B (si las Guest Additions no funcionan).** La consola también puede
empezar directamente por SSH con una llave suya:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/np2_bootstrap -N ""
ssh-copy-id -i ~/.ssh/np2_bootstrap.pub <usuario-normal>@<IP>
```

En la consola de la VM, como root:

```bash
mkdir -p /root/.ssh && cat /home/<usuario-normal>/.ssh/authorized_keys >> /root/.ssh/authorized_keys
```

En `config.json` ponga `"transport": "ssh"`, `"user": "root"` y
`"key": "~/.ssh/np2_bootstrap"`, reinicie la consola y **Probar conexión**.

---

## 3. Llave SSH de root (3.1.2) — hacer primero

Todo lo demás se ejecuta por SSH después de este paso.

1. **Antes** (para el video): desde la terminal del Mac,
   `ssh root@<IP>` → pide contraseña o la rechaza.
2. **Llave SSH del usuario root** → marque la casilla → **Configurar llave de root**.
3. Deben salir 9 pasos en verde. El indicador de arriba cambia a
   **SSH con llave**.
4. **Descargar** la llave privada. Lea las recomendaciones de la pantalla.
5. **Después**:
   ```bash
   chmod 600 ~/Downloads/id_ed25519_root_test
   ssh -i ~/Downloads/id_ed25519_root_test root@<IP>    # entra sin contraseña
   ssh -o PubkeyAuthentication=no root@<IP>             # "Permission denied (publickey)"
   ```

Repita este paso con la **VM del balanceador** (elíjala arriba).

---

## 4. Nombre de host y /etc/hosts (3.1.4)

1. **Consultar estado actual** → muestra el nombre y la línea `127.0.1.1`.
2. Nombre `web1`, dominio `lab.local` → **Aplicar nombre de host**.
3. El resultado muestra *Antes: … → Después: web1*.
4. **Comprobar en la VM**:
   ```bash
   hostname; hostnamectl; cat /etc/hosts; getent hosts web1
   ```
   El indicador del prompt (`root@debian`) cambia al volver a iniciar sesión.

---

## 5. Instalar y eliminar aplicaciones (3.1.1)

1. Escriba `htop tree` → **Consultar estado** (no instalados).
2. **Instalar** (tarda; no cierre la página). Debe terminar con
   *htop: instalado (versión)*.
3. **Comprobar en la VM**: `htop` abre; `dpkg -l htop tree`.
4. **Eliminar** con la casilla de purga marcada → estado *no instalado*.
5. Pruebas de error para el video:
   - `paquetenoexiste` → **Instalar**: mensaje claro de que no existe.
   - `openssh-client` → **Eliminar**: se cancela porque arrastraría
     `openssh-server` y cortaría el acceso. No se cambia nada.

---

## 6. Pantalla de entrada /etc/issue (3.1.3)

1. **Consultar estado actual** → contenido actual y cómo se ve en la consola.
2. Mensaje *Bienvenido al laboratorio de Computación en la Nube*; deje
   marcados nombre de host, fecha, hora e IP (y los que quiera) →
   **Aplicar en /etc/issue**.
3. El resultado muestra **Así se ve en la consola de la VM** con valores reales.
4. **Comprobar en la VM**: mire la **ventana de la VM en VirtualBox** (la
   pantalla de inicio de sesión se actualiza sola; si no, presione Enter o
   cierre sesión). Por SSH no se ve `/etc/issue`.
5. **Restaurar el original** deja la VM como estaba para repetir la prueba.

---

## 7. Usuarios (3.2)

**Crear con llaves y sudo**

1. **Crear usuarios** → **Listar usuarios** (antes).
2. Usuario `ana`, nombre *Ana Pérez*, marque **sudo** y **Generar llaves** →
   **Crear usuario**.
3. Deben salir los pasos en verde, incluido *Iniciar sesión por SSH como ana
   con la llave nueva* y *sudo sin contraseña: correcto*.
4. **Descargar** la llave y **comprobar**:
   ```bash
   chmod 600 ~/Downloads/id_ed25519_ana_test
   ssh -i ~/Downloads/id_ed25519_ana_test ana@<IP> 'id; sudo -n whoami'   # ... root
   ssh -o PubkeyAuthentication=no ana@<IP>                                # rechazado
   ```
5. **Listar usuarios** (después): `ana`, sudo *sí*, contraseña *bloqueada*, 1 llave.

**Crear con contraseña** (sin llaves): usuario `luis`, desmarque llaves,
escriba una contraseña de 8 o más caracteres. Compruebe en la consola de la
VM que `luis` entra con esa contraseña. En **Registro de operaciones** la
contraseña aparece como `********`.

**Eliminar**

1. **Eliminar usuarios** → **Listar usuarios** (antes).
2. `ana`, marque **Eliminar también todos sus archivos** y la confirmación →
   **Eliminar usuario**.
3. **Comprobar en la VM**: `id ana` (no existe), `ls /home` (sin `ana`).
4. Repita con `luis` **sin** la casilla de archivos: `/home/luis` se conserva.
5. Error para el video: intente eliminar `root` → se rechaza.

---

## 8. Servicios con systemd (3.3)

### 8.1 Script de fecha y hora

Cree en el Mac `~/np2/fecha.sh`:

```bash
#!/bin/bash
echo "Ejecutado: $(date '+%Y-%m-%d %H:%M:%S')" >> registro.txt
```

Use ruta **relativa**: el servicio corre como `svc-fecha` dentro de
`/opt/fecha`, y fuera de ahí no tiene permiso de escritura.

1. **Demonios con systemd** → nombre `fecha`, archivos `/Users/<usted>/np2/fecha.sh`,
   ejecutable vacío, tipo **oneshot**, marque *Habilitar e iniciar* →
   **Desplegar servicio**.
2. En **Gestionar una unidad** (queda `fecha`): **start** dos o tres veces.
3. **Comprobar en la VM**:
   ```bash
   cat /opt/fecha/registro.txt        # una línea por cada start
   systemctl status fecha
   ls -l /opt/fecha                   # dueño svc-fecha, sin permisos para otros
   ```

### 8.2 Catálogo de libros

1. Compile el catálogo **para Linux** con la arquitectura de la VM:
   ```bash
   GOOS=linux GOARCH=amd64 go build -o catalogo .    # arm64 si la VM es aarch64
   ```
   Si compila para macOS, la consola lo detecta y avisa antes de transferir.
2. Ponga en una carpeta el ejecutable y lo que necesita (plantillas,
   estáticos, base de datos).
3. Nombre `catalogo`, archivos `/Users/<usted>/catalogo`, ejecutable
   `catalogo`, tipo **simple**. Si el catálogo recibe el puerto por argumento
   o variable, póngalo (p. ej. `PORT=8080`). Si usa el puerto 80, marque
   *Permitir puertos menores que 1024* → **Desplegar servicio**.
4. Debe terminar en *activo: active*. Abra `http://<IP>:<puerto>` en el Mac.
5. Botones sobre `catalogo`, grabando cada uno: **stop** (la página deja de
   responder), **start**, **restart**, **status**, **disable** y **enable**
   (en la VM: `systemctl is-enabled catalogo`). Reinicie la VM después de
   **enable** para mostrar que arranca solo.
6. Error para el video: unidad `ssh` → **stop** → se rechaza.
7. **Listar servicios desplegados** y, para dejar la VM limpia,
   **Desinstalar servicio**.

> Deje el catálogo **desplegado y activo** si lo va a usar como servidor del
> backend en el paso 9.

---

## 9. Balanceador HAProxy (3.4)

### 9.1 Servidores web del backend

Necesita al menos dos servidores web. Una forma de prepararlos con la propia consola:

- **Servidor 1**: la VM de pruebas con el catálogo del paso 8.2 (puerto 8080, por ejemplo).
- **Servidor 2**: una VM del disco multiconexión. Agréguela a `config.json`:
  ```json
  {
    "id": "web2", "label": "VM web 2",
    "host": "192.168.1.71", "port": 22, "user": "root", "key": "",
    "transport": "guest",
    "vm_name": "web2", "guest_user": "root",
    "guest_password_env": "NP2_GUEST_PASSWORD_WEB2"
  }
  ```
  Haga `export NP2_GUEST_PASSWORD_WEB2=...`, reinicie la consola, y sobre
  `web2`: **Llave SSH de root** → **Instalar** `apache2` (queda en el puerto 80)
  → opcionalmente **Nombre de host** `web2`.

### 9.2 Pruebas

Elija arriba la **VM del balanceador**.

1. **Consultar estado** (antes): *todavía no hay balanceador configurado*.
2. **Agregar servidor**: `web1`, IP de la VM de pruebas, puerto del catálogo.
   La primera vez se crea el balanceador en el puerto 80.
3. **Agregar servidor**: `web2`, IP de la VM web 2, puerto `80`.
4. **Consultar estado**: los dos en **UP**.
5. **Probar el balanceo**: 6 peticiones alternadas `web1`, `web2`, `web1`…
   También en el navegador: `http://<IP-balanceador>/`, recargando varias
   veces (en las herramientas de desarrollo se ve la cabecera `X-Servidor`).
6. Apague la VM web 2, espere unos 10 segundos → **Consultar estado**: `web2` en **DOWN**;
   **Probar el balanceo**: todo lo atiende `web1`.
7. **Eliminar servidor** `web2` → ya no aparece. **Comprobar en la VM del
   balanceador**: `cat /etc/haproxy/haproxy.cfg` (bloque entre las marcas
   `# >>> NP2` y `# <<< NP2`) y `systemctl status haproxy`.
8. Errores para el video: agregar otra vez `web1` (nombre repetido) o una IP
   inválida.

---

## 10. Problemas comunes

| Mensaje | Qué hacer |
|---|---|
| *No se pudo comunicar con la máquina virtual* | VM encendida, IP correcta en `config.json`, `ping <IP>`. |
| *no se encuentra la llave privada* | Ejecute **Llave SSH de root** sobre esa VM (o use el plan B). |
| *la variable de entorno … está vacía* | `export NP2_GUEST_PASSWORD_…='…'` en la misma terminal y reinicie `./np2auto`. |
| *La transferencia de archivos requiere el canal SSH* | Primero **Llave SSH de root** sobre esa VM. |
| *el ejecutable es un binario de macOS* | Compile con `GOOS=linux GOARCH=amd64` (o `arm64`). |
| El servicio queda *activating* o *failed* | Lea el `systemctl status` de la pantalla; en la VM: `journalctl -u <nombre> -n 50`. |
| HAProxy marca un servidor **DOWN** | En el balanceador: `timeout 3 bash -c '</dev/tcp/<IP>/<puerto>' && echo responde`. Si no responde, ¿está activo el servicio web en esa VM? |
| *Host no permitido* en el navegador | Abra exactamente `http://127.0.0.1:8088`. |
| *token CSRF inválido* | Reinició la consola: recargue la página. |
