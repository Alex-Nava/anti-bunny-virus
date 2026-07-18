"""
Simulador de ataque tipo "fork bomb" (creación acelerada de procesos).
Genera procesos hijos de forma controlada para probar la detección de
process_monitoring en anti_bunny.py.

Tiene un tope de seguridad (MAX_CHILDREN) y limpia sus propios hijos al
terminar, para que NUNCA se convierta en una fork bomb real aunque el
sentinel no lo detecte a tiempo.
"""

import subprocess
import sys
import time

CHILDREN_PER_BURST = 3   # cuántos procesos genera por ciclo
SLEEP_SECONDS = 0.1       # qué tan rápido genera procesos
MAX_CHILDREN = 60         # freno de seguridad: nunca pasa de esto

CHILD_CMD = [sys.executable, "-c", "import time; time.sleep(5)"]

print("--- [SIMULADOR] Iniciando creación acelerada de procesos ---")
children = []

try:
    while len(children) < MAX_CHILDREN:
        for _ in range(CHILDREN_PER_BURST):
            p = subprocess.Popen(CHILD_CMD)
            children.append(p)
        print(f"[RABBIT-FORK] Procesos hijos creados: {len(children)}")
        time.sleep(SLEEP_SECONDS)
    print(f"[SIMULADOR] Tope de seguridad ({MAX_CHILDREN} procesos) alcanzado.")
except KeyboardInterrupt:
    print("\n[-] Ataque de procesos detenido.")
finally:
    print("[SIMULADOR] Limpiando procesos hijos...")
    for p in children:
        if p.poll() is None:
            p.kill()