import requests
from pymongo import MongoClient, errors
from datetime import datetime, timedelta, timezone
import time

# Configuración de MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["vulnerabilidades"]
coleccion = db["nvd"]

# Rango de fechas: últimos 5 días
hoy = datetime.now(timezone.utc)
hace_5_dias = hoy - timedelta(days=5)
fecha_inicio = hace_5_dias.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
fecha_fin = hoy.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

# API base
base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
results_per_page = 200
start_index = 0
total_insertados = 0

while True:
    params = {
        "lastModStartDate": fecha_inicio,
        "lastModEndDate": fecha_fin,
        "resultsPerPage": results_per_page,
        "startIndex": start_index
    }

    try:
        response = requests.get(base_url, params=params)
        if response.status_code != 200:
            print(f"Error en la petición: {response.status_code}")
            break

        data = response.json()
        vulnerabilidades = data.get("vulnerabilities", [])

        if not vulnerabilidades:
            print("No quedan más resultados para procesar.")
            break

        for item in vulnerabilidades:
            cve = item["cve"]
            cve_id = cve.get("id")

            # Verificar si ya existe en la base
            if coleccion.find_one({"cve_id": cve_id}):
                print(f"[-] {cve_id} ya existe. Saltando.")
                continue

            descripcion = cve["descriptions"][0]["value"] if cve.get("descriptions") else ""

            # Documento simplificado sin productos ni métricas
            doc = {
                "cve_id": cve_id,
                "titulo": descripcion,
                "descripcion": descripcion,
                "fecha_publicacion": cve.get("published"),
                "fecha_modificacion": cve.get("lastModified"),
                "cwe_id": cve.get("weaknesses", [{}])[0].get("description", [{}])[0].get("value", ""),
                "referencias": [ref["url"] for ref in cve.get("references", [])],
                "fuente": "NVD"
            }

            # Insertar en MongoDB
            coleccion.insert_one(doc)
            total_insertados += 1
            print(f"[+] Insertado {cve_id}")

        start_index += results_per_page
        time.sleep(1)

    except Exception as e:
        print(f"[!] Error: {e}")
        break

print(f"\n✅ CVEs insertados: {total_insertados}")
