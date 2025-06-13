from flask import Flask
from flask_pymongo import PyMongo

app = Flask(__name__)
app.config['MONGO_URI'] = 'mongodb://localhost:27017/conferencia_jovenes'
app.config['SECRET_KEY'] = 'clave_secreta_para_login'
app.config['UPLOAD_FOLDER'] = 'uploads'

mongo = PyMongo(app)
