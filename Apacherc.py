#!/usr/bin/env python3
"""
apacherc.py — Apache Recon Checker
====================================
Herramienta de reconocimiento pasivo/activo para detectar rutas sensibles y
malas configuraciones comunes en servidores Apache durante evaluaciones de
seguridad AUTORIZADAS.

Uso:
    python3 apacherc.py --url http://target [opciones]
    python3 apacherc.py --url-list dominios.txt [opciones]

Ejemplos:
    python3 apacherc.py --url https://target.com --save-all
    python3 apacherc.py --url-list dominios.txt --threads 3 --delay 0.3 --save-json

Notas:
- Solo debe usarse contra objetivos para los que tengas autorización explícita.
- El script únicamente comprueba códigos de respuesta HTTP y cabeceras/cuerpo
  públicos; no explota nada ni intenta acceder a contenido protegido.
- Throttling consciente de WAF (pocos hilos + delay configurable), rotación
  de User-Agent y detección de falsos positivos (soft-404 / cuerpo vacío).

Autor:  Frib1t
Repo:   https://github.com/Frib1t/apacherc
Licencia: Apache License 2.0
"""

import argparse
import concurrent.futures
import hashlib
import json
import random
import signal
import string
import sys
import threading
import time
from datetime import datetime
from urllib.parse import urljoin

try:
    import requests
except ImportError:
    print("[!] Falta la librería 'requests'. Instálala con: pip install -r requirements.txt")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Colores ANSI (estilo terminal, sin dependencias externas)
# ---------------------------------------------------------------------------
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"
    MAGENTA = "\033[95m"

CHECK = f"{C.GREEN}✔{C.RESET}"
CROSS = f"{C.RED}✘{C.RESET}"
WARN = f"{C.YELLOW}⚠{C.RESET}"
LOCK = f"{C.MAGENTA}🔒{C.RESET}"
DOT = f"{C.GRAY}•{C.RESET}"

VERDICT_STYLE = {
    "EXPUESTO": (CHECK, C.GREEN),
    "REDIRECCIÓN": (WARN, C.YELLOW),
    "PROHIBIDO": (LOCK, C.MAGENTA),
    "AUTENTICACIÓN REQUERIDA": (LOCK, C.MAGENTA),
    "NO ENCONTRADO": (DOT, C.GRAY),
    "ERROR": (CROSS, C.RED),
    "VACÍO (falso positivo)": (DOT, C.GRAY),
    "PÁGINA GENÉRICA (falso positivo)": (DOT, C.GRAY),
}

# ---------------------------------------------------------------------------
# Rotación de User-Agents (reduce huella y ayuda a esquivar reglas simples de WAF)
# ---------------------------------------------------------------------------
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

# ---------------------------------------------------------------------------
# Base de datos embebida de rutas sensibles (categorizada según el checklist)
# ---------------------------------------------------------------------------
CHECKLIST = {
    "Información y Estado del Servidor": {
        "/server-status": "Muestra peticiones/IPs en tiempo real (debería estar restringido a localhost)",
        "/server-info": "Expone configuración completa de Apache: módulos, rutas, versiones",
        "/config.status": "Revela opciones de compilación si el servidor se compiló manualmente",
    },
    "Archivos Sensibles y Configuración": {
        "/.htaccess": "Puede contener reglas de acceso",
        "/.htpasswd": "Puede contener hashes de contraseñas",
        "/.git/HEAD": "Indica repositorio Git expuesto (posible código fuente completo)",
        "/.git/config": "Configuración del repositorio Git expuesta",
        "/.svn/entries": "Repositorio SVN expuesto",
        "/.env": "Puede contener credenciales de base de datos y variables de entorno",
        "/phpinfo.php": "Revela versión de PHP, extensiones, variables de entorno, rutas absolutas",
        "/info.php": "Igual que phpinfo.php",
    },
    "Directorios por Defecto y Manuales": {
        "/manual/": "Manual de Apache; confirma servidor y a veces versión exacta",
        "/icons/": "Directorio estándar; si tiene listado activado, indica mala configuración",
        "/cgi-bin/": "Scripts ejecutables; históricamente vulnerable (ej. Shellshock)",
    },
    "Rutas de Administración": {
        "/phpmyadmin/": "Gestión de bases de datos MySQL/MariaDB",
        "/webmin/": "Panel de control del sistema",
        "/vhost/": "Información sobre otros sitios alojados",
        "/virtualhosts/": "Información sobre otros sitios alojados",
    },
    "Backups y Temporales (requiere un archivo base conocido, ej. index.php)": {
        "/index.php.bak": "Posible backup de código fuente",
        "/index.php.old": "Posible backup de código fuente",
        "/index.php~": "Archivo temporal de Gedit/Vim",
        "/.index.php.swp": "Archivo swap de Vim",
    },
}

INTERESTING_HEADERS = ["Server", "X-Powered-By", "Via", "X-AspNet-Version"]

VERSION = "1.0.0"

BANNER = f"""{C.CYAN}{C.BOLD}
   _____                     __         __________  _____
  /  _  \\  ______  _____   __| _/______ \\______   \\/  ___/
 /  /_\\  \\ \\____ \\ \\__  \\ / __ |/  ___/  |       _/\\___ \\
/    |    \\|  |_> > / __ \\_/ /_/ |\\___ \\   |    |   \\/    \\
\\____|__  /|   __/ (____  /\\____ |____  >  |____|_  /_______ \\
        \\/ |__|         \\/      \\/    \\/          \\/        \\/{C.RESET}
{C.GRAY}        Apache Recon Checker  v{VERSION}  —  by Frib1t{C.RESET}
"""

lock = threading.Lock()
results = []
stop_event = threading.Event()


def sigint_handler(signum, frame):
    if not stop_event.is_set():
        stop_event.set()
        print(
            f"\n{WARN} {C.YELLOW}Ctrl+C detectado — deteniendo hilos en curso "
            f"y guardando resultados parciales...{C.RESET}"
        )
    else:
        # Segundo Ctrl+C: salida forzosa inmediata
        print(f"\n{CROSS} {C.RED}Forzando salida.{C.RESET}")
        sys.exit(1)


signal.signal(signal.SIGINT, sigint_handler)


def build_target_list(base_url, extra_wordlist_path=None):
    targets = []
    for category, paths in CHECKLIST.items():
        for path, description in paths.items():
            targets.append({
                "url": urljoin(base_url, path.lstrip("/")),
                "path": path,
                "category": category,
                "description": description,
            })

    if extra_wordlist_path:
        try:
            with open(extra_wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    targets.append({
                        "url": urljoin(base_url, line.lstrip("/")),
                        "path": line,
                        "category": "Wordlist personalizado",
                        "description": "",
                    })
        except FileNotFoundError:
            print(f"[!] No se encontró el wordlist extra: {extra_wordlist_path}")

    return targets


def content_hash(content_bytes):
    return hashlib.sha256(content_bytes or b"").hexdigest()


def get_baseline(session, base_url, timeout):
    """
    Pide una ruta aleatoria que casi seguro no existe, para capturar la
    'firma' (hash + longitud) de la página de error/genérica del servidor.
    Cualquier ruta real que devuelva 200 con el mismo hash es un soft-404,
    no un hallazgo real.
    """
    rand_path = "no-existe-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
    url = urljoin(base_url, rand_path)
    try:
        resp = requests_get_safe(session, url, timeout)
        if resp is None:
            return None
        return {
            "status": resp.status_code,
            "hash": content_hash(resp.content),
            "length": len(resp.content or b""),
        }
    except Exception:
        return None


def requests_get_safe(session, url, timeout):
    try:
        return session.get(
            url, timeout=timeout, allow_redirects=False,
            headers={"User-Agent": random.choice(USER_AGENTS)},
        )
    except requests.exceptions.RequestException:
        return None


def classify(status_code, body_len, body_hash, baseline):
    if status_code is None:
        return "ERROR"
    if status_code in (301, 302, 307, 308):
        return "REDIRECCIÓN"
    if status_code == 403:
        return "PROHIBIDO"
    if status_code == 401:
        return "AUTENTICACIÓN REQUERIDA"
    if status_code == 200:
        if body_len == 0:
            return "VACÍO (falso positivo)"
        if baseline and baseline.get("hash") == body_hash and baseline.get("status") == 200:
            return "PÁGINA GENÉRICA (falso positivo)"
        return "EXPUESTO"
    return "NO ENCONTRADO"


def check_target(entry, session, timeout, delay, baseline):
    if stop_event.is_set():
        return
    time.sleep(delay)  # throttling básico anti-WAF
    if stop_event.is_set():
        return
    ua = random.choice(USER_AGENTS)
    try:
        resp = session.get(
            entry["url"],
            timeout=timeout,
            allow_redirects=False,
            headers={"User-Agent": ua},
        )
        status = resp.status_code
        body = resp.content or b""
        body_len = len(body)
        body_hash = content_hash(body)
        verdict = classify(status, body_len, body_hash, baseline)
        headers_found = {
            h: resp.headers[h] for h in INTERESTING_HEADERS if h in resp.headers
        }
        record = {
            "path": entry["path"],
            "url": entry["url"],
            "category": entry["category"],
            "description": entry["description"],
            "status_code": status,
            "verdict": verdict,
            "content_length": resp.headers.get("Content-Length", str(body_len)),
            "body_length_real": body_len,
            "headers": headers_found,
            "user_agent": ua,
        }
    except requests.exceptions.RequestException as e:
        record = {
            "path": entry["path"],
            "url": entry["url"],
            "category": entry["category"],
            "description": entry["description"],
            "status_code": None,
            "verdict": "ERROR",
            "error_detail": e.__class__.__name__,
            "content_length": None,
            "body_length_real": None,
            "headers": {},
            "user_agent": ua,
        }

    with lock:
        results.append(record)
        print_live(record)


def print_live(record):
    icon, color = VERDICT_STYLE.get(record["verdict"], (DOT, C.GRAY))
    status = record["status_code"] if record["status_code"] else "---"
    verdict_txt = record["verdict"] if record["verdict"] != "ERROR" else f"ERROR ({record.get('error_detail')})"
    print(
        f"  {icon} {C.CYAN}[{status}]{C.RESET} "
        f"{color}{verdict_txt:34s}{C.RESET} {record['path']:30s} "
        f"{C.GRAY}-> {record['url']}{C.RESET}"
    )


def run_scan(base_url, extra_wordlist, threads, delay, timeout):
    targets = build_target_list(base_url, extra_wordlist)
    print(f"{C.BOLD}[*] {len(targets)} rutas a comprobar sobre {base_url}{C.RESET}")
    print(f"{C.GRAY}[*] Hilos: {threads} | Delay: {delay}s | Timeout: {timeout}s | UA rotativo: {len(USER_AGENTS)} agentes{C.RESET}")

    session = requests.Session()

    baseline = get_baseline(session, base_url, timeout)
    if baseline:
        print(
            f"{C.GRAY}[*] Baseline soft-404: status={baseline['status']} "
            f"length={baseline['length']} hash={baseline['hash'][:12]}...{C.RESET}\n"
        )
    else:
        print(f"{C.GRAY}[*] No se pudo calcular baseline soft-404 (se omite ese filtro){C.RESET}\n")

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=threads)
    futures = [
        executor.submit(check_target, entry, session, timeout, delay, baseline)
        for entry in targets
    ]
    try:
        while True:
            done, not_done = concurrent.futures.wait(futures, timeout=0.3)
            if not not_done:
                break
            if stop_event.is_set():
                # cancela lo que aún no ha empezado a ejecutarse
                for f in not_done:
                    f.cancel()
                break
    finally:
        executor.shutdown(wait=not stop_event.is_set(), cancel_futures=stop_event.is_set())


def summarize():
    summary = {}
    for r in results:
        summary.setdefault(r["verdict"], []).append(r["path"])

    SKIP_FROM_SUMMARY = {"NO ENCONTRADO", "VACÍO (falso positivo)", "PÁGINA GENÉRICA (falso positivo)"}

    lines = []
    print(f"\n{C.BOLD}{'=' * 60}{C.RESET}")
    print(f"{C.BOLD}RESUMEN{C.RESET}")
    print(f"{C.BOLD}{'=' * 60}{C.RESET}")
    lines.append("=" * 60)
    lines.append("RESUMEN")
    lines.append("=" * 60)

    for verdict, paths in summary.items():
        if verdict in SKIP_FROM_SUMMARY:
            continue
        icon, color = VERDICT_STYLE.get(verdict, (DOT, C.GRAY))
        print(f"\n{icon} {color}{verdict}{C.RESET} ({len(paths)}):")
        lines.append(f"\n{verdict} ({len(paths)}):")
        for p in paths:
            print(f"    {p}")
            lines.append(f"  - {p}")

    filtrados = sum(len(summary.get(v, [])) for v in ("VACÍO (falso positivo)", "PÁGINA GENÉRICA (falso positivo)"))
    if filtrados:
        print(f"\n{DOT} {C.GRAY}{filtrados} falsos positivos filtrados (vacíos o página genérica del servidor){C.RESET}")
        lines.append(f"\n{filtrados} falsos positivos filtrados (vacíos o página genérica del servidor)")

    return "\n".join(lines)


def save_json(prefix):
    path = f"{prefix}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump({
            "scan_date": datetime.now().isoformat(),
            "results": results,
        }, f, indent=2, ensure_ascii=False)
    return path


def save_txt(prefix, summary_text, base_url):
    path = f"{prefix}.txt"
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"apache_recon.py - Informe de reconocimiento\n")
        f.write(f"Fecha: {datetime.now().isoformat()}\n")
        f.write(f"Objetivo: {base_url}\n")
        f.write("=" * 60 + "\n\n")
        f.write("DETALLE POR RUTA\n")
        f.write("-" * 60 + "\n")
        for r in results:
            status = r["status_code"] if r["status_code"] else "---"
            f.write(f"[{status}] {r['verdict']:24s} {r['path']}\n")
            if r["description"]:
                f.write(f"       -> {r['description']}\n")
            if r["headers"]:
                f.write(f"       Headers: {r['headers']}\n")
        f.write("\n")
        f.write(summary_text + "\n")
    return path


def normalize_base_url(raw, default_scheme):
    raw = raw.strip()
    if not raw:
        return None
    if not raw.startswith("http://") and not raw.startswith("https://"):
        raw = f"{default_scheme}://{raw}"
    if not raw.endswith("/"):
        raw += "/"
    return raw


def load_url_list(path):
    targets = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            targets.append(line)
    return targets


def safe_filename(base_url):
    return base_url.replace("https://", "").replace("http://", "").rstrip("/").replace("/", "_")


def scan_one_target(base_url, args):
    """Escanea un único objetivo, imprime y opcionalmente guarda su propio json/txt. Devuelve sus resultados."""
    global results
    results = []  # reset por objetivo

    print(f"\n{C.BOLD}{C.CYAN}{'#' * 60}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}[*] Objetivo: {base_url}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'#' * 60}{C.RESET}\n")

    run_scan(base_url, args.wordlist, args.threads, args.delay, args.timeout)
    summary_text = summarize()

    if args.save_json or args.save_txt:
        prefix = f"{args.output_prefix}_{safe_filename(base_url)}"
        if args.save_json:
            json_path = save_json(prefix)
            print(f"\n{CHECK} JSON guardado en {C.CYAN}{json_path}{C.RESET}")
        if args.save_txt:
            txt_path = save_txt(prefix, summary_text, base_url)
            print(f"{CHECK} TXT guardado en {C.CYAN}{txt_path}{C.RESET}")

    return list(results)


def main():
    parser = argparse.ArgumentParser(
        description="Reconocimiento de rutas sensibles de Apache (uso autorizado únicamente)"
    )
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("--url", help="URL base de un único objetivo, ej: http://target")
    target_group.add_argument("--url-list", help="Ruta a un .txt con varios dominios/URLs, uno por línea")
    parser.add_argument("--scheme", default="https", choices=["http", "https"],
                         help="Esquema para entradas de --url-list sin http(s):// (default: https)")
    parser.add_argument("--wordlist", help="Ruta a un .txt opcional con paths adicionales a comprobar en cada objetivo")
    parser.add_argument("--threads", type=int, default=2, help="Número de hilos concurrentes (default: 2)")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay entre peticiones por hilo, en segundos (default: 0.5)")
    parser.add_argument("--timeout", type=float, default=5, help="Timeout de cada petición en segundos (default: 5)")
    parser.add_argument("--output-prefix", default="apacherc_results", help="Prefijo de los archivos de salida (.json y .txt)")
    parser.add_argument("--save-json", action="store_true", help="Guardar resultados en un archivo .json")
    parser.add_argument("--save-txt", action="store_true", help="Guardar resultados en un archivo .txt")
    parser.add_argument("--save-all", action="store_true", help="Atajo: equivale a --save-json --save-txt")
    parser.add_argument("--version", action="version", version=f"apacherc.py {VERSION}")
    args = parser.parse_args()

    if args.save_all:
        args.save_json = True
        args.save_txt = True

    print(BANNER)
    print(f"{C.GRAY}    [*] Recuerda: solo contra objetivos con autorización explícita.{C.RESET}\n")

    if args.url:
        base_urls = [normalize_base_url(args.url, args.scheme)]
    else:
        raw_targets = load_url_list(args.url_list)
        base_urls = [normalize_base_url(t, args.scheme) for t in raw_targets]
        print(f"{C.GRAY}[*] {len(base_urls)} objetivos cargados desde {args.url_list}{C.RESET}")

    all_results = {}
    for base_url in base_urls:
        all_results[base_url] = scan_one_target(base_url, args)
        if stop_event.is_set():
            print(f"{C.YELLOW}[*] Escaneo interrumpido por el usuario. Resultados parciales guardados.{C.RESET}")
            break

    if not stop_event.is_set() and len(base_urls) > 1:
        print(f"\n{C.BOLD}{'=' * 60}{C.RESET}")
        print(f"{C.BOLD}RESUMEN GLOBAL ({len(base_urls)} objetivos){C.RESET}")
        print(f"{C.BOLD}{'=' * 60}{C.RESET}")
        for base_url, recs in all_results.items():
            expuestos = [r["path"] for r in recs if r["verdict"] == "EXPUESTO"]
            interesantes = [
                r["path"] for r in recs
                if r["verdict"] not in ("EXPUESTO", "NO ENCONTRADO", "VACÍO (falso positivo)", "PÁGINA GENÉRICA (falso positivo)")
            ]
            icon = CHECK if expuestos else (WARN if interesantes else DOT)
            print(f"  {icon} {base_url} -> {len(expuestos)} expuestos, {len(interesantes)} a revisar")

    sys.exit(1 if stop_event.is_set() else 0)


if __name__ == "__main__":
    main()
