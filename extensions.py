import os
from flask import Flask
from flask_pymongo import PyMongo

app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "clave_secreta_para_login")

app.config['MONGO_URI'] = os.environ.get('MONGO_URI')
try:
    mongo.cx.server_info()  # fuerza la conexión
    print(" Conexión con MongoDB establecida.")
except Exception as e:
    print(f" Error al conectar con MongoDB: {e}")


app.config['UPLOAD_FOLDER'] = 'uploads'

mongo = PyMongo(app)
