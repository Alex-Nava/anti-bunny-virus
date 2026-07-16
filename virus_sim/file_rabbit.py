import os
import time

TARGET_DIR = os.path.join(os.path.dirname(__file__), "temp_test")
os.makedirs(TARGET_DIR, exist_ok=True)
TARGET_FILE = os.path.join(TARGET_DIR, "rabbit_payload.dat")

print("--- [SIMULADOR] Iniciando Ataque de Fichero ---")
CHUNK_1MB = b"X" * (1024 * 1024)

try:
    with open(TARGET_FILE, "wb") as f:
        mb_written = 0
        while True:
            for _ in range(5):
                f.write(CHUNK_1MB)
                mb_written += 1
            f.flush()
            print(f"[RABBIT] Escribiendo: {mb_written} MB en disco...")
            time.sleep(0.1)
except KeyboardInterrupt:
    print("\n[-] Ataque detenido.")