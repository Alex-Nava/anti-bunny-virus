"""
Anti-Bunny Virus Sentinel
=========================
Monitorea en tiempo real tres síntomas de un ataque tipo "conejo" (rabbit virus):

  1. Crecimiento anómalo de archivos en disco       (file_monitoring)
  2. Duplicación real de memoria por proceso         (memory_monitoring)
  3. Creación acelerada de procesos (fork bomb)      (process_monitoring)

Diseño de seguridad (léelo antes de correrlo en tu máquina real):
  - Por defecto corre en modo "solo alerta" (general.enforce = false): detecta
    y loguea, pero NO mata ningún proceso.
  - La memoria NO se evalúa con una tasa instantánea (eso también dispara con
    ráfagas normales de apps reales, por paginación diferida del SO). Se
    evalúa por VENTANAS: cada "check_window_seconds" se toma una foto de la
    memoria de cada proceso y se compara contra la foto anterior. Si la
    memoria se multiplicó por "duplication_factor" o más DENTRO de esa
    ventana, cuenta como una anomalía. Solo se actúa si eso se repite
    "min_consecutive_hits" ventanas seguidas (duplicación sostenida real,
    no una ráfaga de un instante).
  - Los procesos en protected_process_names nunca se tocan.
"""

import os
import sys
import json
import time
import logging
import psutil
from collections import Counter, defaultdict

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
OWN_PID = os.getpid()

DEFAULT_CONFIG = {
    "general": {"check_interval_seconds": 0.3, "enforce": False},
    "file_monitoring": {"target_directory": "./virus_sim/temp_test", "max_mb_per_second": 20.0,
                        "min_consecutive_hits": 3},
    "memory_monitoring": {"check_window_seconds": 2.0, "max_mb_per_second": 60.0,
                          "min_mb_floor": 10.0, "min_consecutive_hits": 2, "ignore_pids": []},
    "process_monitoring": {"max_new_processes_per_sec": 15, "min_consecutive_hits": 3},
    "protected_process_names": [
        "System", "Idle", "Registry", "MemCompression",
        "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
        "services.exe", "lsass.exe", "svchost.exe", "dwm.exe", "explorer.exe",
        "systemd", "init", "kthreadd", "sshd",
    ],
    "logging": {"log_file": "antibunny.log"},
}


def load_config():
    if not os.path.exists(CONFIG_PATH):
        print(f"[!] No se encontró {CONFIG_PATH}. Usando configuración por defecto.")
        return DEFAULT_CONFIG
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            user_cfg = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"[!] Error leyendo config.json ({e}). Usando configuración por defecto.")
        return DEFAULT_CONFIG

    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
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


def is_protected(pid: int, protected_names: set) -> bool:
    if pid == OWN_PID:
        return True
    try:
        name = psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return True
    return name in protected_names


def act_on_suspect(pid: int, reason: str, min_hits: int, cfg, hit_counters: dict, logger: logging.Logger):
    protected_names = set(cfg["protected_process_names"])
    enforce = cfg["general"]["enforce"]

    hit_counters[pid] += 1
    hits = hit_counters[pid]

    try:
        name = psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        name = "desconocido"

    if is_protected(pid, protected_names):
        logger.info(f"[IGNORADO] PID {pid} ({name}) es un proceso protegido. No se toca. Motivo: {reason}")
        return

    if hits < min_hits:
        logger.warning(f"[OBSERVANDO] PID {pid} ({name}) — anomalía {hits}/{min_hits} veces seguidas. "
                        f"Motivo: {reason}. Aún no se actúa.")
        return

    if not enforce:
        logger.warning(f"[SIMULACIÓN] PID {pid} ({name}) superó {min_hits} veces seguidas ({reason}). "
                        f"Con enforce=true, este proceso sería terminado ahora.")
        return

    try:
        proc = psutil.Process(pid)
        proc.kill()
        logger.info(f"[LIQUIDADO] PID {pid} ({name}) terminado tras {hits} anomalías seguidas. Motivo: {reason}")
    except psutil.NoSuchProcess:
        logger.info(f"[INFO] PID {pid} ya no existe (terminó antes de poder matarlo).")
    except psutil.AccessDenied:
        logger.warning(f"[ERROR] Permisos insuficientes para terminar PID {pid}. "
                        f"Ejecuta el sentinel con privilegios de administrador/root.")


def clear_hits(pid: int, hit_counters: dict):
    if pid in hit_counters:
        del hit_counters[pid]


def find_pid_writing_file(file_path: str):
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


def check_file_growth(cfg, last_sizes, elapsed, hit_counters, logger):
    target_dir = os.path.abspath(os.path.join(BASE_DIR, cfg["file_monitoring"]["target_directory"]))
    threshold = cfg["file_monitoring"]["max_mb_per_second"]
    min_hits = cfg["file_monitoring"]["min_consecutive_hits"]

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
                pid = find_pid_writing_file(file_path)
                if pid:
                    logger.warning(f"[ALERTA-DISCO] '{file}' crece a {growth_rate:.2f} MB/s "
                                    f"(límite {threshold} MB/s)")
                    act_on_suspect(pid, f"escritura anómala en {file}", min_hits, cfg, hit_counters, logger)
                else:
                    logger.warning(f"[ALERTA-DISCO] '{file}' crece a {growth_rate:.2f} MB/s, "
                                    f"no se pudo identificar el proceso responsable.")


def check_memory_duplication(cfg, mem_state, now, hit_counters, logger):
    window = cfg["memory_monitoring"]["check_window_seconds"]
    if now - mem_state["last_window_time"] < window:
        return

    threshold = cfg["memory_monitoring"]["max_mb_per_second"]
    floor_mb = cfg["memory_monitoring"]["min_mb_floor"]
    min_hits = cfg["memory_monitoring"]["min_consecutive_hits"]
    ignore_pids = set(cfg["memory_monitoring"].get("ignore_pids", [])) | {OWN_PID}

    baseline = mem_state["baseline"]
    new_baseline = {}

    for proc in psutil.process_iter(['pid', 'memory_info']):
        pid = proc.info['pid']
        if pid in ignore_pids:
            continue
        try:
            mem_mb = proc.info['memory_info'].rss / (1024 * 1024)
        except (psutil.NoSuchProcess, psutil.AccessDenied, TypeError):
            continue

        new_baseline[pid] = mem_mb
        prev_mb = baseline.get(pid)

        if prev_mb is not None and prev_mb >= floor_mb:
            growth_rate = (mem_mb - prev_mb) / window
            if growth_rate >= threshold:
                act_on_suspect(pid, f"memoria crece sostenida a {growth_rate:.1f} MB/s "
                                     f"(ventana {window:.1f}s: {prev_mb:.1f}MB -> {mem_mb:.1f}MB)",
                                min_hits, cfg, hit_counters, logger)
                continue

        clear_hits(pid, hit_counters)

    mem_state["baseline"] = new_baseline
    mem_state["last_window_time"] = now


def check_process_creation(cfg, last_pids, elapsed, hit_counters, logger):
    threshold = cfg["process_monitoring"]["max_new_processes_per_sec"]
    min_hits = cfg["process_monitoring"]["min_consecutive_hits"]

    current_procs = {}
    for proc in psutil.process_iter(['pid', 'ppid']):
        try:
            current_procs[proc.info['pid']] = proc.info['ppid']
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    new_pids = set(current_procs.keys()) - set(last_pids.keys())
    creation_rate = len(new_pids) / elapsed if elapsed > 0 else 0

    if creation_rate > threshold and new_pids:
        parent_counts = Counter(current_procs[pid] for pid in new_pids if current_procs.get(pid))
        if parent_counts:
            suspect_ppid, count = parent_counts.most_common(1)[0]
            logger.warning(f"[ALERTA-PROCESOS] {len(new_pids)} procesos nuevos en {elapsed:.2f}s "
                            f"({creation_rate:.1f} proc/s, límite {threshold} proc/s). "
                            f"PID padre sospechoso: {suspect_ppid} ({count} hijos nuevos)")
            act_on_suspect(suspect_ppid, "posible fork bomb", min_hits, cfg, hit_counters, logger)

    last_pids.clear()
    last_pids.update(current_procs)


def main():
    cfg = load_config()
    logger = setup_logging(cfg["logging"]["log_file"])
    check_interval = cfg["general"]["check_interval_seconds"]
    enforce = cfg["general"]["enforce"]

    logger.info("--- [ANTI-BUNNY SENTINEL] Servicio de Protección Activo ---")
    logger.info(f"[+] Modo: {'ENFORCE (mata procesos)' if enforce else 'SOLO ALERTA (no mata nada)'}")
    logger.info(f"[+] Directorio vigilado: {cfg['file_monitoring']['target_directory']}")
    logger.info(f"[+] Umbral disco: {cfg['file_monitoring']['max_mb_per_second']} MB/s")
    logger.info(f"[+] Umbral memoria: {cfg['memory_monitoring']['max_mb_per_second']} MB/s "
                f"por ventana de {cfg['memory_monitoring']['check_window_seconds']}s, "
                f"{cfg['memory_monitoring']['min_consecutive_hits']} ventanas seguidas")
    logger.info(f"[+] Umbral creación de procesos: "
                f"{cfg['process_monitoring']['max_new_processes_per_sec']} proc/s")

    if not enforce:
        logger.info("[+] Modo seguro: ningún proceso real será terminado. "
                     "Pon \"enforce\": true en config.json para activar la mitigación real.")

    last_sizes = {}
    mem_state = {"last_window_time": time.time(), "baseline": {}}
    last_pids = {p.pid: (p.ppid() if p.is_running() else None) for p in psutil.process_iter()}
    hit_counters = defaultdict(int)
    last_time = time.time()

    try:
        while True:
            time.sleep(check_interval)
            now = time.time()
            elapsed = now - last_time
            last_time = now

            check_file_growth(cfg, last_sizes, elapsed, hit_counters, logger)
            check_memory_duplication(cfg, mem_state, now, hit_counters, logger)
            check_process_creation(cfg, last_pids, elapsed, hit_counters, logger)

    except KeyboardInterrupt:
        logger.info("[-] Servicio Antivirus detenido por el usuario.")


if __name__ == "__main__":
    main()