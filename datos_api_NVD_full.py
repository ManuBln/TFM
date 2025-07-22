import requests
from pymongo import MongoClient
from datetime import datetime
import time

# Conexión a MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["vulnerabilidades"]
coleccion = db["nvd"]

# URL base sin filtro de fecha (trae todos los CVEs disponibles)
base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
results_per_page = 2000  # máximo permitido por la API
start_index = 0
total_insertados = 0

print("🔎 Iniciando descarga completa de CVEs desde la NVD...")

while True:
    params = {
        "resultsPerPage": results_per_page,
        "startIndex": start_index
    }

    try:
        response = requests.get(base_url, params=params)
        if response.status_code != 200:
            print(f"[!] Error en la petición: {response.status_code}")
            break

        data = response.json()
        vulnerabilidades = data.get("vulnerabilities", [])

        if not vulnerabilidades:
            print("✅ No quedan más CVEs por procesar.")
            break

        for item in vulnerabilidades:
            cve = item.get("cve", {})
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
                "fecha_insercion": datetime.utcnow(),
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
        time.sleep(1.5)  # evitar sobrecargar la API

    except Exception as e:
        print(f"[!] Error inesperado: {e}")
        break

print(f"\n✅ Proceso finalizado. CVEs insertados: {total_insertados}")
