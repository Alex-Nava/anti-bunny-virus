# 🛡️ Anti-Bunny Virus Sentinel

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)
![Security](https://img.shields.io/badge/Category-Cybersecurity-red?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active_MVP-success?style=for-the-badge)

Sistema de detección y mitigación en tiempo real para ataques de denegación de servicio local (DoS) provocados por malware de tipo **Rabbit Virus** (escritura masiva en disco) y **Fork Bombs** (agotamiento de la tabla de procesos).

---

## 🎯 Características Principales

- **Monitoreo de I/O en Disco:** Inspección continua del crecimiento volumétrico ($\Delta MB / \Delta t$) en directorios vulnerables.
- **Mitigación Activa por PID:** Identificación del proceso agresor y finalización forzada mediante señales del sistema operativo.
- **Configuración Dinámica:** Control de umbrales y tiempos de muestreo mediante `config.json`.
- **Simulador Incluido:** Entorno seguro en `virus_sim/` para realizar pruebas sin poner en riesgo el sistema operativo.

---

## 📁 Estructura del Proyecto

```text
anti-bunny-virus/
├── anti_bunny.py        # Motor principal de monitoreo y defensa
├── config.json          # Umbrales de detección y parámetros
├── virus_sim/
│   └── file_rabbit.py   # Simulador de ataque de escritura masiva
├── antibunny.log        # Registro persistente de eventos
├── .gitignore
└── README.md
```

---

## 🚀 Instalación y Uso

### 1. Requisitos Previos

Asegúrate de contar con **Python 3.10 o superior** e instala las dependencias requeridas:

```bash
# Crear y activar entorno virtual
python -m venv venv

# Windows
.\venv\Scripts\activate

# Linux/macOS
source venv/bin/activate

# Instalar dependencias
pip install psutil watchdog
```

### 2. Ejecutar la Defensa

Inicia el servicio de protección en una terminal:

```bash
python anti_bunny.py
```

### 3. Probar la Mitigación (Simulador)

En una segunda terminal, ejecuta el simulador de ataque:

```bash
python virus_sim/file_rabbit.py
```

El antivirus detectará la tasa anómala de escritura (**>15 MB/s**) y finalizará automáticamente el proceso malicioso en menos de **1 segundo**.

---

## 🛠️ Tecnologías Utilizadas

- **Python 3.10+**
- **psutil:** Inspección de procesos, PIDs y descriptores de archivos.
- **watchdog:** Monitoreo del sistema de archivos en tiempo real.
- **JSON:** Configuración ligera mediante `config.json`.

---

## 📌 Proyecto y Documentación

- Consulte el [Tablero Kanban de GitHub Projects](https://github.com/users/Alex-Nava/projects) para revisar la planificación, los sprints y el backlog del proyecto.
- Visite la [Wiki del Repositorio](https://github.com/Alex-Nava/anti-bunny-virus/wiki) para conocer la arquitectura detallada, el modelo de amenazas y la documentación técnica.

---

## 📄 Licencia

Este proyecto se distribuye con fines académicos y de investigación en ciberseguridad. Puede adaptarse y ampliarse para fines educativos o experimentales.
