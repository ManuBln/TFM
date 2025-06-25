from flask import Flask, render_template, jsonify
from pymongo import MongoClient

app = Flask(__name__)

# Conexión a MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["vulnerabilidades"]
coleccion = db["nvd"]

@app.route("/api/cves")
def api_cves():
    cves = list(coleccion.find({}, {"_id": 0}))
    return jsonify(cves)

@app.route("/")
def index():
    cves = list(coleccion.find({}, {"_id": 0}))
    return render_template("index.html", cves=cves)

if __name__ == "__main__":
    app.run(debug=True)
