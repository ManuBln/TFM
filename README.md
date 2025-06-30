# 🛡️ Aplicación Web de Análisis de Vulnerabilidades (NVD + CSV)

Este proyecto permite visualizar, almacenar y analizar vulnerabilidades CVE extraídas de la base de datos oficial de NVD, y compararlas con resultados de escáneres en formato CSV (como Qualys). La aplicación incluye una interfaz web desarrollada con Flask, MongoDB, Pandas y Chart.js para visualización de datos, coincidencias y un dashboard profesional.

---

## ✅ Requisitos del sistema

- Python 3.10 o superior
- pip
- MongoDB local (puedes usar MongoDB Atlas si prefieres)
- Git (para clonar el repositorio)

---

## 📦 Instalación paso a paso

Sigue estos pasos para instalar y ejecutar el proyecto correctamente:

```bash
# 1️⃣ Clonar el repositorio
git clone https://github.com/tu-usuario/tu-repo.git
cd tu-repo

# 2️⃣ Crear y activar un entorno virtual
# En Linux/macOS:
python3 -m venv venv
source venv/bin/activate

# En Windows:
python -m venv venv
venv\Scripts\activate

# 3️⃣ Instalar las dependencias
pip install -r requirements.txt

# 4️⃣ Verificar que MongoDB esté corriendo (por defecto en localhost:27017)
# Si usas MongoDB Atlas, edita la URI en app.py

Antes de usar la web, ejecuta el siguiente script para descargar los últimos CVEs desde la API oficial de NVD:
python datos_api_NVD.py
🚀 Ejecutar la aplicación
python app.py

Después abre tu navegador en:

http://127.0.0.1:5000

🧪 Funcionalidades principales
/ → Vista principal: listado de CVEs con buscador y paginación

/subir_csv → Subida de archivos CSV desde navegador

/coincidencias → Visualización de coincidencias entre NVD y CSV

/dashboard → Dashboard visual con gráficas interactivas

/api/cves → API JSON de todos los CVEs almacenados


