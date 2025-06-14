from flask import Flask
from flask_pymongo import PyMongo

app = Flask(__name__)
app.config['MONGO_URI'] = os.environ.get('MONGO_URI')
app.config['SECRET_KEY'] = 'clave_secreta_para_login'
app.config['UPLOAD_FOLDER'] = 'uploads'

mongo = PyMongo(app)
