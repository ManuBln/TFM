# 🛡️ VulnMatch: Aplicación Web de Análisis y Cruce de Vulnerabilidades (NVD + CSV)

Este proyecto permite visualizar, almacenar y analizar vulnerabilidades CVE extraídas de la base de datos oficial de NVD y compararlas con resultados de escáneres en formato CSV (como Qualys). Incluye una interfaz web profesional desarrollada con Flask, MongoDB, Pandas y Chart.js para la visualización, detección de coincidencias y generación de dashboards interactivos.

💡 Hecho con: 🐍 Flask + 🍃 MongoDB + 🧠 Pandas + 📊 Chart.js

---

✅ **Requisitos del sistema**  
- Python 3.10 o superior  
- pip  
- MongoDB local (o Atlas si prefieres)  
- Git (para clonar el repositorio)  

---

📦 **Instalación paso a paso**

Sigue estos pasos para instalar y ejecutar el proyecto correctamente:

🗃️ **Instalación de MongoDB**

Para que esta aplicación funcione, necesitas tener el servidor de base de datos MongoDB ejecutándose en tu sistema.

🔹 Si estás en Ubuntu o Debian:  
```bash
sudo rm /etc/apt/sources.list.d/mongodb-org-7.0.list
echo "deb [signed-by=/usr/share/keyrings/mongodb-server-6.0.gpg] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/6.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-6.0.list
sudo apt update
sudo apt install -y mongodb-org
mongod --version
sudo systemctl start mongod
sudo systemctl enable mongod
```

🔹 Verifica que esté funcionando:  
```bash
sudo systemctl status mongodb
```

Por defecto, la aplicación se conecta a:  
MongoClient("mongodb://localhost:27017/")  
Si usas MongoDB Atlas, edita la URI en `app.py`.

🔧 **Configuración del entorno**

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

# 4️⃣ Crear carpeta de subida (si no existe)
mkdir uploads
```

📄 Si no tienes el archivo requirements.txt, puedes generarlo con:  
```bash
pip freeze > requirements.txt
```

Ejemplo mínimo de requirements.txt:  
```txt
Flask
pymongo
pandas
Werkzeug
```

---

📥 **Carga y actualización de CVEs desde la API de NVD**

Antes de usar la web, ejecuta uno de los siguientes scripts para descargar los CVEs desde la API oficial de NVD:

- `python datos_api_NVD.py` → Descarga los últimos 5 días de CVEs.
- `python datos_api_NVD_mejorado.py` → Descarga los últimos 30 días (ajustable en el script).
- `python datos_api_NVD_full.py` → Descarga masiva de todos los CVEs disponibles (puede tardar mucho).

Estos scripts almacenan los CVEs en la colección `nvd` de MongoDB.

---

🚀 **Ejecutar la aplicación**

```bash
python app.py
```

Después abre tu navegador en:  
http://127.0.0.1:5000

---

🧪 **Funcionalidades principales**

- `/` → Vista principal con listado de CVEs, buscador y paginación.
- `/subir_csv` → Subida de archivos CSV desde el navegador, procesamiento y cruce automático con la base NVD.
- `/coincidencias` → Visualización de coincidencias entre vulnerabilidades del CSV y la base NVD.
- `/dashboard` → Dashboard visual con gráficas interactivas (top activos, severidad, parcheables, recientes, top 10).
- `/api/cves` → API REST que devuelve todos los CVEs almacenados en formato JSON.

---

📁 **Estructura real del proyecto**

```
TFM/
├── app.py
├── datos_api_NVD.py
├── datos_api_NVD_mejorado.py
├── datos_api_NVD_full.py
├── requirements.txt
├── README.md
├── uploads/
│   ├── insertar_CVS_BBDD.py
│   ├── Semana1.csv
│   ├── Semana2.csv
│   ├── Semana3.csv
│   └── Semana4.csv
├── Informes/
│   ├── insertar_CVS_BBDD.py
│   ├── Semana1.csv
│   ├── Semana2.csv
│   ├── Semana3.csv
│   └── Semana4.csv
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── subir_csv.html
│   ├── coincidencias.html
│   ├── dashboard.html
│   └── subida_exitosa.html
├── static/
│   └── vulnmatch.css
└── app_web/ (entorno virtual Python)
```

---

🔄 **Carga masiva de CSVs y cruce con NVD**

Además de la subida web, puedes usar los scripts:
- `uploads/insertar_CVS_BBDD.py` o `Informes/insertar_CVS_BBDD.py` para cargar automáticamente todos los CSV de una carpeta y cruzarlos con la base NVD. Puedes personalizar la ruta de los CSV con la variable de entorno `CARPETA_CSV`.

---

🎨 **Interfaz y visualización**

- **Dark mode** y diseño responsive.
- Tablas con badges de severidad y CVSS.
- Dashboard con gráficas interactivas (Chart.js): top activos, severidad, parcheables, vulnerabilidades recientes y top 10.
- Plantillas HTML en `templates/` y estilos en `static/vulnmatch.css`.

---

🔌 **Dependencias principales**

```
Flask
pymongo
pandas
Werkzeug
requests
Chart.js (CDN en dashboard)
```
(Consulta `requirements.txt` para la lista completa y versiones exactas)

---

🎯 ¿Listo para analizar tus vulnerabilidades de forma profesional?  
¡Ejecuta tu servidor y comienza! 🚀
