import pandas as pd
from pymongo import MongoClient
from datetime import datetime
import glob
import os
import unicodedata

# Conexión MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["vulnerabilidades"]

# Colecciones
csv_coleccion = db["csv_vulnerabilidades"]
nvd_coleccion = db["nvd"]
coincidentes_coleccion = db["registros_nvd_csv_coincidentes"]

# Permitir configurar la ruta de los CSV por variable de entorno
carpeta_csv = os.environ.get("CARPETA_CSV", "/home/mblnt/Escritorio/TFM/Informes")
csv_files = glob.glob(os.path.join(carpeta_csv, "Semana*.csv"))

# Contadores
total_insertados = 0
total_en_coincidentes = 0

# Función para normalizar severidad y CVE
def normaliza(s):
    s = str(s or "").strip().lower()
    s = unicodedata.normalize('NFKD', s).encode('ascii', 'ignore').decode('ascii')
    return s

for file_path in csv_files:
    print(f"\n📄 Procesando archivo: {file_path}")
    df = pd.read_csv(file_path)

    for _, row in df.iterrows():
        cve_id = row.get("CVE")
        if not cve_id:
            continue
        cve_id = normaliza(cve_id)
        # Convertir fila en documento
        doc_csv = row.to_dict()
        doc_csv["cve_id"] = cve_id
        doc_csv["fuente"] = "Qualys CSV"
        doc_csv["fecha_insercion"] = datetime.utcnow()
        # Normalizar severidad si existe
        if "Severity" in doc_csv:
            doc_csv["Severity"] = normaliza(doc_csv["Severity"])

        # Insertar en csv_vulnerabilidades
        csv_coleccion.insert_one(doc_csv)
        total_insertados += 1
        print(f"[+] Insertado {cve_id} en csv_vulnerabilidades")

        # Verificar si existe en nvd
        doc_nvd = nvd_coleccion.find_one({"cve_id": cve_id})
        if doc_nvd:
            combinado = {
                "cve_id": cve_id,
                "fecha_match": datetime.utcnow(),
                "datos_csv": doc_csv,
                "datos_nvd": doc_nvd
            }
            coincidentes_coleccion.insert_one(combinado)
            total_en_coincidentes += 1
            print(f"    ↪ Coincide con NVD → guardado en registros_nvd_csv_coincidentes")

# Resumen
print(f"\n✅ Total insertados en csv_vulnerabilidades: {total_insertados}")
print(f"🧩 Total con match guardados en registros_nvd_csv_coincidentes: {total_en_coincidentes}")
