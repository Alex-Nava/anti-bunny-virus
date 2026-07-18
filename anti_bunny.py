"""
Anti-Bunny Virus Sentinel
=========================
Monitorea en tiempo real tres síntomas de un ataque tipo "conejo" (rabbit virus):

  1. Crecimiento anómalo de archivos en disco       (file_monitoring)
  2. Crecimiento anómalo de memoria por proceso      (memory_monitoring)
  3. Creación acelerada de procesos (fork bomb)      (process_monitoring)

Todos los umbrales se leen de config.json (no hay valores hardcodeados).
Los eventos se registran en consola y en el archivo de log configurado.
"""

import os
import sys
import json
import time
import logging
import psutil
from collections import Counter

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
OWN_PID = os.getpid()

# Nombres de ejecutable protegidos contra terminación accidental por falsos positivos
WHITELIST_NAMES = {
    "chrome.exe",
    "Code.exe",
    "msedge.exe",
    "firefox.exe",
    "MemCompression",
    "explorer.exe",
    "svchost.exe",
    # "python.exe",  # Cuidado: si el simulador usa python, asegúrate de correrlo mediante script explícito
}

DEFAULT_CONFIG = {
    "file_monitoring": {"target_directory": "./virus_sim/temp_test", "max_mb_per_second": 20.0},
    "memory_monitoring": {"max_mb_per_second": 150.0, "ignore_pids": []},
    "process_monitoring": {"max_new_processes_per_sec": 10},
    "general": {"check_interval_seconds": 0.5},
    "logging": {"log_file": "antibunny.log"},
}


def load_config():
    """Carga config.json; si falta o está corrupto, usa valores por defecto."""
    if not os.path.exists(CONFIG_PATH):
        print(f"[!] No se encontró {CONFIG_PATH}. Usando configuración por defecto.")
        return DEFAULT_CONFIG
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            user_cfg = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"[!] Error leyendo config.json ({e}). Usando configuración por defecto.")
        return DEFAULT_CONFIG

    cfg = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy
    for section, values in user_cfg.items():
        if section in cfg and isinstance(values, dict):
            cfg[section].update(values)
        else:
            cfg[section] = values
    return cfg


def setup_logging(log_file_name: str):
    log_path = os.path.join(BASE_DIR, log_file_name)
    logger = logging.getLogger("antibunny")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    fmt = logging.Formatter("[%(asctime)s] %(message)s", "%Y-%m-%d %H:%M:%S")

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(fmt)
    logger.addHandler(console_handler)

    return logger


def kill_process(pid: int, logger: logging.Logger, reason: str):
    """Intenta terminar un proceso agresor identificado por PID."""
    if pid == OWN_PID:
        return False
    try:
        proc = psutil.Process(pid)
        name = proc.name()

        # Protección adicional: verificar lista blanca antes de matar
        if name in WHITELIST_NAMES:
            logger.info(f"[OMITIDO] PID {pid} ({name}) está en la lista blanca y no será finalizado.")
            return False

        proc.kill()
        logger.info(f"[LIQUIDADO] PID {pid} ({name}) terminado. Motivo: {reason}")
        return True
    except psutil.NoSuchProcess:
        logger.info(f"[INFO] PID {pid} ya no existe (terminó antes de poder matarlo).")
    except psutil.AccessDenied:
        logger.warning(f"[ERROR] Permisos insuficientes para terminar PID {pid}. "
                       f"Ejecuta el sentinel con privilegios de administrador/root.")
    return False


def find_pid_writing_file(file_path: str):
    """Busca qué proceso tiene abierto el archivo que está creciendo de forma anómala."""
    for proc in psutil.process_iter(['pid']):
        if proc.pid == OWN_PID:
            continue
        try:
            for f in proc.open_files():
                if os.path.abspath(f.path) == os.path.abspath(file_path):
                    return proc.pid
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return None


def check_file_growth(cfg, last_sizes, elapsed, logger):
    target_dir = os.path.abspath(os.path.join(BASE_DIR, cfg["file_monitoring"]["target_directory"]))
    threshold = cfg["file_monitoring"]["max_mb_per_second"]

    if not os.path.exists(target_dir):
        return

    for root, _, files in os.walk(target_dir):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                size_mb = os.path.getsize(file_path) / (1024 * 1024)
            except FileNotFoundError:
                continue

            prev_size = last_sizes.get(file_path, size_mb)
            last_sizes[file_path] = size_mb
            growth_rate = (size_mb - prev_size) / elapsed if elapsed > 0 else 0

            if growth_rate > threshold:
                logger.warning(f"[ALERTA-DISCO] '{file}' crece a {growth_rate:.2f} MB/s "
                               f"(límite {threshold} MB/s)")
                pid = find_pid_writing_file(file_path)
                if pid:
                    kill_process(pid, logger, reason=f"escritura anómala en {file}")
                else:
                    logger.warning(f"[ALERTA-DISCO] No se pudo identificar el proceso que "
                                   f"escribe en '{file}'.")


def check_memory_growth(cfg, last_mem, elapsed, logger):
    threshold = cfg["memory_monitoring"]["max_mb_per_second"]
    ignore_pids = set(cfg["memory_monitoring"].get("ignore_pids", [])) | {OWN_PID}

    for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
        pid = proc.info['pid']
        name = proc.info['name']

        if pid in ignore_pids or name in WHITELIST_NAMES:
            continue

        try:
            mem_mb = proc.info['memory_info'].rss / (1024 * 1024)
        except (psutil.NoSuchProcess, psutil.AccessDenied, TypeError):
            continue

        prev_mem = last_mem.get(pid, mem_mb)
        last_mem[pid] = mem_mb
        growth_rate = (mem_mb - prev_mem) / elapsed if elapsed > 0 else 0

        if growth_rate > threshold:
            logger.warning(f"[ALERTA-MEMORIA] PID {pid} ({name}) crece a "
                           f"{growth_rate:.2f} MB/s (límite {threshold} MB/s)")
            kill_process(pid, logger, reason="duplicación/crecimiento anómalo de memoria")

    alive_pids = {p.pid for p in psutil.process_iter()}
    for pid in list(last_mem.keys()):
        if pid not in alive_pids:
            del last_mem[pid]


def check_process_creation(cfg, last_pids, elapsed, logger):
    threshold = cfg["process_monitoring"]["max_new_processes_per_sec"]

    current_procs = {}
    for proc in psutil.process_iter(['pid', 'ppid']):
        try:
            current_procs[proc.info['pid']] = proc.info['ppid']
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    new_pids = set(current_procs.keys()) - set(last_pids.keys())
    creation_rate = len(new_pids) / elapsed if elapsed > 0 else 0

    if creation_rate > threshold and new_pids:
        logger.warning(f"[ALERTA-PROCESOS] {len(new_pids)} procesos nuevos en {elapsed:.2f}s "
                       f"({creation_rate:.1f} proc/s, límite {threshold} proc/s)")

        parent_counts = Counter(current_procs[pid] for pid in new_pids if current_procs.get(pid))
        if parent_counts:
            suspect_ppid, count = parent_counts.most_common(1)[0]
            logger.warning(f"[ALERTA-PROCESOS] PID padre sospechoso: {suspect_ppid} "
                           f"(generó {count} procesos nuevos)")
            kill_process(suspect_ppid, logger, reason="posible fork bomb")

    last_pids.clear()
    last_pids.update(current_procs)


def main():
    cfg = load_config()
    logger = setup_logging(cfg["logging"]["log_file"])
    check_interval = cfg["general"]["check_interval_seconds"]

    logger.info("--- [ANTI-BUNNY SENTINEL] Servicio de Protección Activo ---")
    logger.info(f"[+] Directorio vigilado: {cfg['file_monitoring']['target_directory']}")
    logger.info(f"[+] Umbral disco: {cfg['file_monitoring']['max_mb_per_second']} MB/s")
    logger.info(f"[+] Umbral memoria: {cfg['memory_monitoring']['max_mb_per_second']} MB/s")
    logger.info(f"[+] Umbral creación de procesos: "
                f"{cfg['process_monitoring']['max_new_processes_per_sec']} proc/s")

    last_sizes = {}
    last_mem = {}
    last_pids = {p.pid: (p.ppid() if p.is_running() else None) for p in psutil.process_iter()}
    last_time = time.time()

    try:
        while True:
            time.sleep(check_interval)
            now = time.time()
            elapsed = now - last_time
            last_time = now

            check_file_growth(cfg, last_sizes, elapsed, logger)
            check_memory_growth(cfg, last_mem, elapsed, logger)
            check_process_creation(cfg, last_pids, elapsed, logger)

    except KeyboardInterrupt:
        logger.info("[-] Servicio Antivirus detenido por el usuario.")


if __name__ == "__main__":
    main()