from flask import Flask, render_template, request, jsonify
from pymongo import MongoClient
import os
import pandas as pd
from werkzeug.utils import secure_filename
from datetime import datetime
from collections import Counter

app = Flask(__name__)

# Conexión a MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["vulnerabilidades"]

# Carpeta de subida
UPLOAD_FOLDER = os.path.join(os.getcwd(), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Index con búsqueda y paginación
@app.route("/")
def index():
    page = int(request.args.get("page", 1))
    per_page = 4
    q = request.args.get("q", "").strip()
    coleccion = db["nvd"]

    query = {}
    if q:
        query = {
            "$or": [
                {"cve_id": {"$regex": q, "$options": "i"}},
                {"descripcion": {"$regex": q, "$options": "i"}}
            ]
        }

    total_cves = coleccion.count_documents(query)
    total_pages = (total_cves + per_page - 1) // per_page
    skip = (page - 1) * per_page

    cves = list(coleccion.find(query, {"_id": 0}).skip(skip).limit(per_page))

    return render_template("index.html", cves=cves, page=page, total_pages=total_pages, q=q)

# API de CVEs
@app.route("/api/cves")
def api_cves():
    coleccion = db["nvd"]
    cves = list(coleccion.find({}, {"_id": 0}))
    return jsonify(cves)

# Subir y procesar CSV
@app.route("/subir_csv", methods=["GET", "POST"])
def subir_csv():
    if request.method == "POST":
        archivo = request.files.get("archivo")
        if not archivo:
            return "No se envió ningún archivo", 400

        filename = secure_filename(archivo.filename)
        ruta = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        archivo.save(ruta)

        df = pd.read_csv(ruta)
        csv_col = db["csv_vulnerabilidades"]
        nvd_col = db["nvd"]
        coincidencias_col = db["registros_nvd_csv_coincidentes"]

        total_csv = 0
        total_coinciden = 0

        for _, row in df.iterrows():
            cve_id = row.get("CVE")
            if not cve_id:
                continue

            doc_csv = row.to_dict()
            doc_csv["cve_id"] = cve_id
            doc_csv["fuente"] = "Qualys CSV"
            doc_csv["fecha_insercion"] = datetime.utcnow()

            csv_col.insert_one(doc_csv)
            total_csv += 1

            doc_nvd = nvd_col.find_one({"cve_id": cve_id})
            if doc_nvd:
                combinado = {
                    "cve_id": cve_id,
                    "fecha_match": datetime.utcnow(),
                    "datos_csv": doc_csv,
                    "datos_nvd": doc_nvd
                }
                coincidencias_col.insert_one(combinado)
                total_coinciden += 1

        mensaje = f"✅ CSV procesado: {total_csv} insertados, {total_coinciden} coincidencias encontradas."
        return render_template("subida_exitosa.html", mensaje=mensaje)

    return render_template("subir_csv.html")

# Coincidencias
@app.route("/coincidencias")
def coincidencias():
    coleccion = db["registros_nvd_csv_coincidentes"]
    coincidencias = list(coleccion.find({}, {"_id": 0}).limit(100))
    return render_template("coincidencias.html", coincidencias=coincidencias)

# Dashboard refinado y profesional
@app.route("/dashboard")
def dashboard():
    coincidencias = db["registros_nvd_csv_coincidentes"]
    total = coincidencias.count_documents({})

    severidades = Counter()
    activos = Counter()
    parcheables = Counter()
    recientes = []

    # Definir variantes de severidades
    criticos = {"critical", "crítico", "critico", "crítica", "critica"}
    altos = {"high", "alta", "alto"}
    medias = {"medium", "media", "medio"}
    bajas = {"low", "baja", "bajo"}

    def normaliza(s):
        import unicodedata
        s = str(s or "").strip().lower()
        s = unicodedata.normalize('NFKD', s).encode('ascii', 'ignore').decode('ascii')
        return s

    def severidad_key(sev):
        if sev in criticos:
            return 4
        elif sev in altos:
            return 3
        elif sev in medias:
            return 2
        elif sev in bajas:
            return 1
        return 0

    total_criticos = 0
    total_altos = 0
    vulner_list = []
    now = datetime.utcnow()
    ultimas_24h = now.timestamp() - 24*3600

    for item in coincidencias.find():
        doc_csv = item.get("datos_csv", {})
        doc_nvd = item.get("datos_nvd", {})
        severity_raw = doc_csv.get("Severity", "unknown")
        severity = normaliza(severity_raw)
        severidades[severity] += 1

        if severity in criticos:
            total_criticos += 1
        elif severity in altos:
            total_altos += 1

        activo = doc_csv.get("Asset Name", "Desconocido")
        activos[activo] += 1

        parcheable = str(doc_csv.get("Vuln Patchable", "Desconocido")).strip().capitalize()
        parcheables[parcheable] += 1

        cve_id = item.get("cve_id", "")
        descripcion = doc_nvd.get("descripcion", "")
        cvss = doc_nvd.get("cvss")
        fecha_match = item.get("fecha_match")
        asset = doc_csv.get("Asset Name", "Desconocido")

        vulner_list.append({
            "cve_id": cve_id,
            "severity": severity,
            "descripcion": descripcion,
            "fecha_match": fecha_match,
            "asset": asset,
            "cvss": cvss
        })

        # Recientes (últimas 24h)
        if fecha_match:
            try:
                fecha_dt = datetime.fromisoformat(fecha_match) if isinstance(fecha_match, str) else fecha_match
                if fecha_dt.timestamp() > ultimas_24h:
                    recientes.append({
                        "cve_id": cve_id,
                        "severity": severity,
                        "descripcion": descripcion,
                        "fecha_match": fecha_dt.strftime("%Y-%m-%d %H:%M"),
                        "asset": asset,
                        "cvss": cvss
                    })
            except Exception:
                pass

    # Ordenar top 10 por severidad y CVSS (más crítico primero)
    vulner_list_sorted = sorted(
        vulner_list,
        key=lambda v: (severidad_key(v["severity"]), v["cvss"] if v["cvss"] is not None else -1, v["cve_id"]),
        reverse=True
    )
    top_10_vulner = vulner_list_sorted[:10]
    recientes = sorted(recientes, key=lambda v: v["fecha_match"], reverse=True)
    top_activos = dict(activos.most_common(5))

    # --- PAGINACIÓN PARA VULNER RECENTES ---
    page = int(request.args.get("recientes_page", 1))
    per_page = 4
    total_recientes = len(recientes)
    total_pages = (total_recientes + per_page - 1) // per_page
    start = (page - 1) * per_page
    end = start + per_page
    recientes_paged = recientes[start:end]

    return render_template(
        "dashboard.html",
        total=total,
        severidades=severidades,
        activos=top_activos,
        parcheables=parcheables,
        total_criticos=total_criticos,
        total_altos=total_altos,
        top_10_vulner=top_10_vulner,
        donut_severidades=dict(severidades),
        recientes=recientes_paged,
        recientes_page=page,
        recientes_total_pages=total_pages
    )

if __name__ == "__main__":
    app.run(debug=True)
