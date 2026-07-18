# 🛡️ Anti-Bunny Virus Sentinel

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)
![Security](https://img.shields.io/badge/Category-Cybersecurity-red?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active_MVP-success?style=for-the-badge)

Sistema de detección y mitigación en tiempo real para ataques de denegación de servicio local (DoS) provocados por malware de tipo **Rabbit/Wabbit Virus**: duplicación de memoria, escritura masiva en disco y agotamiento de la tabla de procesos (fork bomb).

---

## 🎯 Características Principales

- **Monitoreo de I/O en disco:** crecimiento volumétrico (`ΔMB/Δt`) en directorios vigilados.
- **Monitoreo de memoria por proceso, basado en ventanas de tiempo:** mide `ΔMB` cada `check_window_seconds`, no una tasa instantánea (ver [[Modelo de Amenazas]] para el porqué).
- **Monitoreo de creación de procesos:** detecta ráfagas de procesos nuevos (fork bomb) y ubica al proceso padre responsable.
- **Anomalía sostenida, no un solo golpe:** ningún síntoma se considera un ataque hasta que se repite `min_consecutive_hits` veces seguidas.
- **Modo `enforce` explícito:** por defecto (`enforce: false`) el sistema solo alerta, nunca mata procesos. Solo mitiga activamente si se activa a propósito.
- **Lista de procesos protegidos:** procesos críticos del sistema operativo nunca se terminan, sin importar el modo.
- **Mitigación activa por PID:** identifica al proceso agresor (por archivo abierto, por consumo de memoria o por relación padre-hijo) y lo termina.
- **Configuración dinámica:** todos los umbrales viven en `config.json`, sin valores hardcodeados en el código.
- **Simuladores incluidos:** tres escenarios de prueba aislados en `virus_sim/`, cada uno con un tope de seguridad interno.

---

## 📁 Estructura del Proyecto

```text
anti-bunny-virus/
├── anti_bunny.py            # Motor principal: disco + memoria + procesos
├── config.json               # Umbrales, modo enforce y lista de procesos protegidos
├── virus_sim/
│   ├── file_rabbit.py         # Simulador: escritura masiva en disco
│   ├── memory_rabbit.py        # Simulador: duplicación de memoria
│   └── fork_rabbit.py          # Simulador: creación acelerada de procesos
├── antibunny.log              # Registro persistente de eventos (se genera al ejecutar, no se versiona)
├── .gitignore
└── README.md
```

---

## 🚀 Instalación y Uso

### 1. Requisitos previos

```bash
python -m venv venv

# Windows
.\venv\Scripts\Activate.ps1
# Linux/macOS
source venv/bin/activate

pip install psutil
```

### 2. Configurar (`config.json`)

```json
{
  "general": { "check_interval_seconds": 0.3, "enforce": false },
  "file_monitoring": { "target_directory": "./virus_sim/temp_test", "max_mb_per_second": 20.0, "min_consecutive_hits": 3 },
  "memory_monitoring": { "check_window_seconds": 2.0, "max_mb_per_second": 60.0, "min_mb_floor": 10.0, "min_consecutive_hits": 2, "ignore_pids": [] },
  "process_monitoring": { "max_new_processes_per_sec": 15, "min_consecutive_hits": 3 },
  "protected_process_names": ["System", "explorer.exe", "svchost.exe", "..."],
  "logging": { "log_file": "antibunny.log" }
}
```

> ⚠️ **`enforce: false` es el valor seguro para primer contacto con el proyecto.** Solo cámbialo a `true` cuando vayas a probar la mitigación real, y hazlo mientras corres los simuladores, no en tu sesión de trabajo normal. Ver [[Modelo de Amenazas]] para entender por qué existe este seguro.

### 3. Ejecutar

```bash
python anti_bunny.py
```

### 4. Probar cada tipo de ataque

Con el sentinel corriendo en una terminal (y el venv activado en ambas), en una segunda terminal:

```bash
python virus_sim/file_rabbit.py
python virus_sim/memory_rabbit.py
python virus_sim/fork_rabbit.py
```

Cada simulador tiene un tope de seguridad interno: aunque el sentinel no lo detecte, el propio simulador se detiene solo.

---

## 🧪 Evidencia de que funciona

Ver [[Pruebas y Validación]] para el protocolo completo y la tabla de resultados. Resumen del comportamiento esperado:

| Escenario | Resultado esperado |
|---|---|
| Uso normal del equipo (Chrome, VS Code, etc.) corriendo junto al sentinel en modo `enforce: true` | Cero procesos terminados |
| `file_rabbit.py` | Detectado y terminado en segundos |
| `memory_rabbit.py` | Detectado tras 2 ventanas de crecimiento sostenido y terminado |
| `fork_rabbit.py` | Detectado y terminado el proceso padre |

---

## 🛠️ Tecnologías Utilizadas

- **Python 3.10+**
- **psutil:** inspección de procesos, PIDs, memoria y descriptores de archivos abiertos.
- **JSON:** configuración en tiempo de ejecución.

---

## 📌 Documentación

- [Wiki del Repositorio](https://github.com/Alex-Nava/anti-bunny-virus/wiki): modelo de amenazas, arquitectura, estado del arte y evidencia de pruebas.

## 📄 Licencia

Proyecto con fines académicos y de investigación en ciberseguridad.
