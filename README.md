# 🛡️ Anti-Bunny Virus Sentinel

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)
![Security](https://img.shields.io/badge/Category-Cybersecurity-red?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active_MVP-success?style=for-the-badge)

Sistema de detección y mitigación en tiempo real para ataques de denegación de servicio local (DoS) provocados por malware de tipo **Rabbit/Wabbit Virus**: duplicación de memoria, escritura masiva en disco y agotamiento de la tabla de procesos (fork bomb).

---

## 🎯 Características Principales

- **Monitoreo de I/O en disco:** crecimiento volumétrico (`ΔMB/Δt`) en directorios vigilados.
- **Monitoreo de memoria por proceso:** detecta duplicación/crecimiento anómalo de RAM (`ΔMB/Δt`) por PID.
- **Monitoreo de creación de procesos:** detecta ráfagas de procesos nuevos (fork bomb) y ubica al proceso padre responsable.
- **Mitigación activa por PID:** identifica al proceso agresor (por archivo abierto, por consumo de memoria o por relación padre-hijo) y lo termina.
- **Configuración dinámica:** todos los umbrales viven en `config.json`, sin valores hardcodeados en el código.
- **Simuladores incluidos:** tres escenarios de prueba aislados en `virus_sim/`, cada uno con un tope de seguridad para no comprometer tu máquina real si el sentinel fallara en detectarlo.

---

## 📁 Estructura del Proyecto

```text
anti-bunny-virus/
├── anti_bunny.py            # Motor principal: disco + memoria + procesos
├── config.json               # Umbrales de detección y parámetros
├── virus_sim/
│   ├── file_rabbit.py         # Simulador: escritura masiva en disco
│   ├── memory_rabbit.py        # Simulador: duplicación de memoria
│   └── fork_rabbit.py          # Simulador: creación acelerada de procesos
├── antibunny.log              # Registro persistente de eventos (se genera al ejecutar)
├── .gitignore
└── README.md
```

---

## 🚀 Instalación y Uso

### 1. Requisitos previos

```bash
python -m venv venv

# Windows
.\venv\Scripts\activate
# Linux/macOS
source venv/bin/activate

pip install psutil
```

> Nota: la versión actual usa polling con `psutil`, no `watchdog`. Si más adelante migras a `watchdog` para el monitoreo de archivos, actualiza esta sección y el `pip install`.

### 2. Configurar umbrales (`config.json`)

```json
{
  "file_monitoring": { "target_directory": "./virus_sim/temp_test", "max_mb_per_second": 20.0 },
  "memory_monitoring": { "max_mb_per_second": 25.0, "ignore_pids": [] },
  "process_monitoring": { "max_new_processes_per_sec": 5 },
  "general": { "check_interval_seconds": 0.3 },
  "logging": { "log_file": "antibunny.log" }
}
```

### 3. Ejecutar la defensa

```bash
python anti_bunny.py
```

En Windows/Linux, si el sentinel no puede terminar algún proceso por permisos, ejecútalo como administrador/root — sobre todo necesario para el monitoreo de procesos.

### 4. Probar cada tipo de ataque (simuladores)

Con el sentinel corriendo en una terminal, abre una segunda terminal y ejecuta uno a la vez:

```bash
# Ataque de disco
python virus_sim/file_rabbit.py

# Ataque de memoria
python virus_sim/memory_rabbit.py

# Ataque de procesos (fork bomb controlada)
python virus_sim/fork_rabbit.py
```

Cada simulador tiene un **tope de seguridad interno** (ver comentarios en cada archivo) para que, aunque el sentinel no lo detecte, el propio simulador se detenga solo antes de afectar tu sistema real.

---

## 🧪 Cómo saber que funciona (evidencia para la sustentación)

Para cada uno de los 3 simuladores, corre la prueba y guarda:

1. **Captura de la terminal del sentinel** en el momento de la alerta (debe mostrarse `[ALERTA-DISCO]`, `[ALERTA-MEMORIA]` o `[ALERTA-PROCESOS]` y luego `[LIQUIDADO]`).
2. **Captura de la terminal del simulador** mostrando que fue terminado abruptamente (el proceso muere sin llegar a su tope de seguridad).
3. **El fragmento correspondiente de `antibunny.log`** (ábrelo después de la prueba, cada evento queda con timestamp).
4. **Un cronómetro o timestamp** del momento en que iniciaste el simulador vs. el momento del `[LIQUIDADO]` en el log, para reportar la latencia de detección real.

Guarda estas 4 evidencias por cada ataque en la Wiki, en la página `Pruebas y Validación` (usa la tabla que ya te dejé ahí). Con eso demuestras que no solo escribiste código, sino que lo probaste contra los tres síntomas descritos en el enunciado (memoria, disco y procesos).

### Prueba de "falso positivo" (opcional pero recomendable)

Copia un archivo grande (por ejemplo 200 MB) a una carpeta normal *fuera* de `virus_sim/temp_test` y confirma que el sentinel **no** dispara ninguna alerta — así demuestras que el umbral está calibrado y no mata procesos legítimos.

---

## 🛠️ Tecnologías Utilizadas

- **Python 3.10+**
- **psutil:** inspección de procesos, PIDs, memoria y descriptores de archivos abiertos.
- **JSON:** configuración mediante `config.json`, leída en tiempo de ejecución (sin valores hardcodeados).

---

## 📌 Proyecto y Documentación

- Consulta el [Tablero Kanban de GitHub Projects](https://github.com/users/Alex-Nava/projects) para la planificación y el backlog.
- Visita la [Wiki del Repositorio](https://github.com/Alex-Nava/anti-bunny-virus/wiki) para el modelo de amenazas, arquitectura, estado del arte y evidencia de pruebas.

---

## 📄 Licencia

Este proyecto se distribuye con fines académicos y de investigación en ciberseguridad. Puede adaptarse y ampliarse para fines educativos o experimentales.
