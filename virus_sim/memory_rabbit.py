"""
Simulador de ataque tipo "conejo" en MEMORIA.
Duplica/crece su propio consumo de RAM de forma controlada para probar
la detección de memory_monitoring en anti_bunny.py.

Tiene un tope de seguridad (MAX_MB) para que, si el sentinel falla en
detectarlo, el script se detenga solo antes de comprometer el sistema real.
"""

import time

CHUNK_MB = 10          # cuánto crece cada iteración
SLEEP_SECONDS = 0.1    # qué tan rápido crece (más chico = más agresivo)
MAX_MB = 800           # freno de seguridad: nunca pasa de esto

print("--- [SIMULADOR] Iniciando duplicación de memoria ---")
blocks = []
total_mb = 0

try:
    while total_mb < MAX_MB:
        blocks.append(bytearray(CHUNK_MB * 1024 * 1024))
        total_mb += CHUNK_MB
        print(f"[RABBIT-MEM] Memoria reservada: {total_mb} MB")
        time.sleep(SLEEP_SECONDS)
    print(f"[SIMULADOR] Tope de seguridad ({MAX_MB} MB) alcanzado. Deteniendo solo.")
except KeyboardInterrupt:
    print("\n[-] Ataque de memoria detenido.")