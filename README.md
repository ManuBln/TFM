# 🛡️ Aplicación Web de Análisis de Vulnerabilidades (NVD + CSV)

Este proyecto permite visualizar, almacenar y analizar vulnerabilidades CVE extraídas de la base de datos oficial de NVD, y compararlas con resultados de escáneres en formato CSV (como Qualys). La aplicación incluye una interfaz web desarrollada con Flask, MongoDB, Pandas y Chart.js para visualización de datos, coincidencias y un dashboard profesional.

✅ Requisitos del sistema  
Python 3.10 o superior  
pip  
MongoDB local (puedes usar MongoDB Atlas si prefieres)  
Git (para clonar el repositorio)

📦 Instalación paso a paso  
Sigue estos pasos para instalar y ejecutar el proyecto correctamente:

🗃️ Instalación de MongoDB  
Para que esta aplicación funcione, necesitas tener el servidor de base de datos MongoDB ejecutándose en tu máquina o accesible remotamente.

sudo rm /etc/apt/sources.list.d/mongodb-org-7.0.list
echo "deb [signed-by=/usr/share/keyrings/mongodb-server-6.0.gpg] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/6.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-6.0.list
sudo apt update
sudo apt install -y mongodb-org
mongod --version
sudo systemctl start mongod
sudo systemctl enable mongod
sudo systemctl status mongod

3. Verifica que MongoDB funcione (cliente)
mongosh
o
mongo

🔹 Verifica que esté funcionando:

sudo systemctl status mongodb  

🔹 También puedes probar la conexión con:

mongo --eval 'db.runCommand({ connectionStatus: 1 })'  

Por defecto, la aplicación se conecta a:  
MongoClient("mongodb://localhost:27017/")  
Si usas MongoDB Atlas, edita la URI en app.py.

🔧 Configuración del entorno

1️⃣ Clonar el repositorio:  
git clone https://github.com/tu-usuario/tu-repo.git  
cd tu-repo  

2️⃣ Crear y activar un entorno virtual  
En Linux/macOS:  
sudo apt install python3.12-venv

python3 -m venv venv  
source venv/bin/activate  

En Windows:  
python -m venv venv  
source venv/bin/activate

deactivate
3️⃣ Instalar dependencias  
pip install -r requirements.txt  

4️⃣ Crear carpeta de subida (si no existe):  
mkdir uploads  

📄 Si no tienes el archivo requirements.txt, puedes generarlo con:  
pip freeze > requirements.txt  

Ejemplo mínimo de contenido de requirements.txt:  
Flask  
pymongo  
pandas  
Werkzeug  

📥 Cargar CVEs desde la API de NVD  
Antes de usar la web, ejecuta el siguiente script para descargar los últimos CVEs desde la API oficial de NVD:  
python datos_api_NVD.py  

🚀 Ejecutar la aplicación  
python app.py  

Después abre tu navegador en:  
http://127.0.0.1:5000  

🧪 Funcionalidades principales  
/               → Vista principal con CVEs, buscador y paginación  
/subir_csv      → Subida de archivos CSV desde navegador  
/coincidencias  → Visualización de coincidencias entre CSV y NVD  
/dashboard      → Dashboard con gráficas interactivas  
/api/cves       → API JSON con todos los CVEs  

📁 Estructura del proyecto  
tu-repo/  
├── app.py  
├── datos_api_NVD.py  
├── requirements.txt  
├── README.md  
├── uploads/  
├── templates/  
│   ├── base.html  
│   ├── index.html  
│   ├── subir_csv.html  
│   ├── coincidencias.html  
│   └── dashboard.html  
├── static/  
└── .gitignore  

¿Listo para analizar tus vulnerabilidades de forma profesional?  
¡Ejecuta tu servidor y comienza! 🚀
