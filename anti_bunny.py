import os
import time
import psutil

# Monitorear carpeta temp_test dentro de virus_sim
TARGET_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "virus_sim", "temp_test"))
MAX_MB_PER_SEC = 15.0  # Si escribe a más de 15 MB/s, lo mata

print("--- [ANTI-BUNNY SENTINEL] Servicio de Protección Activo ---")
print(f"[+] Monitoreando carpeta: {TARGET_DIR}")
print(f"[+] Umbral máximo permitido: {MAX_MB_PER_SEC} MB/s\n")

last_sizes = {}
last_time = time.time()

try:
    while True:
        time.sleep(0.3)
        now = time.time()
        elapsed = now - last_time
        last_time = now

        if not os.path.exists(TARGET_DIR):
            continue

        for root, _, files in os.walk(TARGET_DIR):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    size_mb = os.path.getsize(file_path) / (1024 * 1024)
                    prev_size = last_sizes.get(file_path, size_mb)
                    last_sizes[file_path] = size_mb

                    growth_rate = (size_mb - prev_size) / elapsed if elapsed > 0 else 0

                    if growth_rate > MAX_MB_PER_SEC:
                        print(f"\n[⚠️ ALERTA DE SEGURIDAD] Tasa anómala detectada en: {file}")
                        print(f"[!] Velocidad actual: {growth_rate:.2f} MB/s | Límite: {MAX_MB_PER_SEC} MB/s")
                        print("[🛡️ DEFENSA] Buscando proceso agresor...")

                        # Rastrear proceso que tiene abierto el archivo o que corre en la carpeta
                        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                            try:
                                cmdline = proc.info.get('cmdline')
                                if cmdline and 'file_rabbit.py' in ' '.join(cmdline):
                                    print(f"[💥 LIQUIDADO] Eliminando proceso malicioso -> PID {proc.info['pid']} ({proc.info['name']})")
                                    proc.kill()
                                    print("[✅ ÉXITO] Amenaza neutralizada. Ataque detenido.")
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                pass
                except FileNotFoundError:
                    pass
except KeyboardInterrupt:
    print("\n[-] Antivirus detenido.")