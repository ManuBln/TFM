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
            if not cve_id:
                continue

            # Descripción en inglés
            descripcion = ""
            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    descripcion = desc.get("value", "").strip()
                    break

            # Obtener CVSS v3 o v2 y normalizar a float
            cvss = None
            metrics = cve.get("metrics", {})
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics:
                    try:
                        cvss = float(metrics[key][0]["cvssData"]["baseScore"])
                    except Exception:
                        cvss = None
                    break

            # CWE
            cwe_id = ""
            weaknesses = cve.get("weaknesses", [])
            if weaknesses and "description" in weaknesses[0]:
                cwe_id = weaknesses[0]["description"][0].get("value", "")

            # Referencias
            referencias = [ref["url"] for ref in cve.get("references", []) if "url" in ref]

            doc = {
                "cve_id": cve_id,
                "descripcion": descripcion,
                "fecha_publicacion": cve.get("published"),
                "fecha_modificacion": cve.get("lastModified"),
                "cwe_id": cwe_id,
                "referencias": referencias,
                "fuente": "NVD",
                "cvss": cvss
            }

            existente = coleccion.find_one({"cve_id": cve_id})
            if existente:
                if existente.get("fecha_modificacion") != doc["fecha_modificacion"]:
                    coleccion.update_one({"cve_id": cve_id}, {"$set": doc})
                    print(f"[~] {cve_id} actualizado.")
                else:
                    print(f"[-] {cve_id} sin cambios.")
                continue

            coleccion.insert_one(doc)
            total_insertados += 1
            print(f"[+] Insertado {cve_id}")

        start_index += results_per_page
        time.sleep(1)

    except Exception as e:
        print(f"[!] Error: {e}")
        break

print(f"\n✅ CVEs insertados: {total_insertados}")
