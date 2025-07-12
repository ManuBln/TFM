import requests
from pymongo import MongoClient
from datetime import datetime, timedelta, timezone
import time

# Configuración de MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["vulnerabilidades"]
coleccion = db["nvd"]

# 🔁 Cambiar rango a últimos N días
DIAS = 30
hoy = datetime.now(timezone.utc)
hace_N_dias = hoy - timedelta(days=DIAS)
fecha_inicio = hace_N_dias.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
fecha_fin = hoy.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

# API base
base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
results_per_page = 200
start_index = 0
total_insertados = 0
total_actualizados = 0

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

            descripcion = ""
            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    descripcion = desc.get("value", "")
                    break

            nuevo_doc = {
                "cve_id": cve_id,
                "descripcion": descripcion,
                "fecha_publicacion": cve.get("published"),
                "fecha_modificacion": cve.get("lastModified"),
                "cwe_id": cve.get("weaknesses", [{}])[0].get("description", [{}])[0].get("value", ""),
                "referencias": [ref["url"] for ref in cve.get("references", [])],
                "fuente": "NVD"
            }

            existente = coleccion.find_one({"cve_id": cve_id})

            if existente:
                if existente.get("fecha_modificacion") != nuevo_doc["fecha_modificacion"]:
                    coleccion.update_one({"cve_id": cve_id}, {"$set": nuevo_doc})
                    total_actualizados += 1
                    print(f"[~] {cve_id} actualizado.")
                else:
                    print(f"[-] {cve_id} sin cambios.")
            else:
                coleccion.insert_one(nuevo_doc)
                total_insertados += 1
                print(f"[+] Insertado {cve_id}")

        start_index += results_per_page
        time.sleep(1)

    except Exception as e:
        print(f"[!] Error: {e}")
        break

print(f"\n✅ CVEs insertados: {total_insertados}")
print(f"🔁 CVEs actualizados: {total_actualizados}")
