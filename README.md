# apacherc.py — Apache Recon Checker

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-stable-brightgreen)

Herramienta de reconocimiento pasivo/activo para detectar **rutas sensibles y
malas configuraciones comunes en servidores Apache**, pensada para
evaluaciones de seguridad autorizadas (pentesting, auditorías, CTFs propios).

Comprueba automáticamente un checklist de rutas típicamente mal expuestas
(`/server-status`, `/.git/`, `/.env`, paneles de administración, backups,
etc.), filtra falsos positivos y soporta múltiples objetivos a la vez.

```
   _____                     __         __________  _____
  /  _  \  ______  _____   __| _/______ \______   \/  ___/
 /  /_\  \ \____ \ \__  \ / __ |/  ___/  |       _/\___ \
/    |    \|  |_> > / __ \_/ /_/ |\___ \   |    |   \/    \
\____|__  /|   __/ (____  /\____ |____  >  |____|_  /_______ \
        \/ |__|         \/      \/    \/          \/        \/
        Apache Recon Checker  v1.0.0  —  by Frib1t
```

## Características

- ✅ **Checklist embebido** de rutas sensibles, categorizado: info del
  servidor, archivos de configuración, directorios por defecto, paneles de
  administración, backups/temporales.
- ✅ **Multi-target**: un único `--url` o una lista completa con `--url-list`.
- ✅ **Multi-threaded** con throttling configurable (`--threads`, `--delay`)
  para no disparar reglas de WAF.
- ✅ **Rotación de User-Agent** en cada petición.
- ✅ **Filtro de falsos positivos**:
  - Baseline soft-404 (hash SHA-256 de una ruta aleatoria inexistente):
    detecta páginas de error genéricas que responden `200`.
  - Detección de cuerpo vacío (`200` con `Content-Length: 0`).
- ✅ **Manejo limpio de Ctrl+C**: guarda lo recolectado hasta el momento y
  sale sin trazas de error.
- ✅ **Wordlist adicional** opcional (`--wordlist`) para sumar rutas propias
  al checklist embebido.
- ✅ **Salida con colores** e iconos por veredicto, y exportación opcional a
  JSON y/o TXT (`--save-json` / `--save-txt` / `--save-all`).

## Instalación

```bash
git clone https://github.com/Frib1t/apacherc.git
cd apacherc
pip install -r requirements.txt
```

Requiere Python 3.8+.

## Uso

```bash
# Un único objetivo
python3 apacherc.py --url https://target.com

# Varios objetivos desde un archivo (uno por línea)
python3 apacherc.py --url-list dominios.txt

# Guardar resultados en JSON y TXT
python3 apacherc.py --url https://target.com --save-all

# Ajustar concurrencia y throttling frente a WAF
python3 apacherc.py --url https://target.com --threads 2 --delay 0.5

# Añadir rutas propias al checklist
python3 apacherc.py --url https://target.com --wordlist extra_paths.txt
```

### Opciones

| Flag | Descripción | Default |
|---|---|---|
| `--url` | URL base de un único objetivo | — |
| `--url-list` | Archivo `.txt` con varios dominios/URLs, uno por línea | — |
| `--scheme` | Esquema (`http`/`https`) para entradas de `--url-list` sin esquema explícito | `https` |
| `--wordlist` | `.txt` opcional con rutas adicionales | — |
| `--threads` | Hilos concurrentes | `2` |
| `--delay` | Delay entre peticiones por hilo (segundos) | `0.5` |
| `--timeout` | Timeout de cada petición (segundos) | `5` |
| `--output-prefix` | Prefijo de los archivos de salida | `apacherc_results` |
| `--save-json` | Guarda resultados en `.json` | desactivado |
| `--save-txt` | Guarda resultados en `.txt` | desactivado |
| `--save-all` | Atajo: `--save-json` + `--save-txt` | desactivado |
| `--version` | Muestra la versión | — |

`--url` y `--url-list` son mutuamente excluyentes.

## Ejemplo de salida

```
✔ [200] EXPUESTO                          /phpmyadmin/                   -> https://target.com/phpmyadmin/
🔒 [403] PROHIBIDO                         /.env                          -> https://target.com/.env
• [200] VACÍO (falso positivo)            /server-info                   -> https://target.com/server-info
• [200] PÁGINA GENÉRICA (falso positivo)  /config.status                 -> https://target.com/config.status
```

## Checklist incluido

| Categoría | Ejemplos |
|---|---|
| Información y estado del servidor | `/server-status`, `/server-info`, `/config.status` |
| Archivos sensibles y configuración | `/.htaccess`, `/.htpasswd`, `/.git/`, `/.env`, `/phpinfo.php` |
| Directorios por defecto | `/manual/`, `/icons/`, `/cgi-bin/` |
| Rutas de administración | `/phpmyadmin/`, `/webmin/`, `/vhost/` |
| Backups y temporales | `*.bak`, `*.old`, `*~`, `*.swp` |

## ⚠️ Uso responsable

Esta herramienta está pensada **únicamente para evaluaciones de seguridad
autorizadas**: pentesting con contrato/alcance firmado, auditorías internas,
laboratorios propios o CTFs. El autor no se hace responsable del mal uso de
esta herramienta. Escanear sistemas sin autorización explícita puede ser
ilegal según la legislación aplicable.

## Licencia

MIT — ver [LICENSE](LICENSE).
