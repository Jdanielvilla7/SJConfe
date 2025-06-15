import os
from flask import Flask
from flask_pymongo import PyMongo

app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "clave_secreta_para_login")
app.config['MONGO_URI'] = os.environ.get('MONGO_URI')

# app.config['SECRET_KEY'] = 'tu_clave_secreta'
# app.config['MONGO_URI'] = 'mongodb://localhost:27017/conferencia_jovenes'

app.config['UPLOAD_FOLDER'] = 'uploads'

mongo = PyMongo(app)

try:
    mongo.cx.server_info()  # fuerza la conexión
    print(" Conexión con MongoDB establecida.")
except Exception as e:
    print(f" Error al conectar con MongoDB: {e}")