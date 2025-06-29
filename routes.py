from flask import Blueprint, render_template, redirect, url_for, request, session, flash, jsonify, sessions,current_app
from flask_login import LoginManager
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from datetime import datetime


from datetime import datetime
import firebase_admin
from firebase_admin import credentials, messaging
import pandas as pd
import os

from extensions import mongo, app
from functools import wraps
from flask import abort
import logging

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
)

routes = Blueprint('routes', __name__)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'routes.login'



# Ruta para el service worker de Firebase
@routes.route('/firebase-messaging-sw.js')
def sw():
    return current_app.send_static_file('firebase-messaging-sw.js')

def rol_requerido(rol_permitido):
    def decorador(f):
        @wraps(f)
        def decorador_funcion(*args, **kwargs):
            if 'rol' not in session or session['rol'] != rol_permitido:
                abort(403)  # Prohibido
            return f(*args, **kwargs)
        return decorador_funcion
    return decorador


# MODELO DE USUARIO
class Usuario:
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.password_hash = user_data['password']
        self.rol = user_data.get('rol', 'staff')  # Por defecto, 'staff'

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return self.id

    @staticmethod
    def get(user_id):
        user_data = mongo.db.usuarios.find_one({'_id': ObjectId(user_id)})
        return Usuario(user_data) if user_data else None

        user_data = mongo.db.usuarios.find_one({'_id': ObjectId(user_id)})
        return Usuario(user_data) if user_data else None

@login_manager.user_loader
def load_user(user_id):
    return Usuario.get(user_id)

@routes.route('/')
def index():
    return redirect(url_for('routes.login'))

# RUTA: Registro
@routes.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        nombre=request.form['name']
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        rol = request.form.get('rol', 'staff','coordinator')  # staff por defecto
        autoriza=0
        mongo.db.usuarios.insert_one({'username': username, 'password': password, 'rol': rol})
        flash('Usuario creado correctamente.')
        return redirect(url_for('routes.login'))
    return render_template('registro.html')


# RUTA: Login
@routes.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            username = request.form['username']
            password = request.form['password']

            user = mongo.db.usuarios.find_one({'username': username})

            if user and check_password_hash(user['password'], password):
                usuario = Usuario(user)
                session['user_id'] = usuario.get_id()
                session['username'] = usuario.username
                session['rol'] = usuario.rol
                return redirect(url_for('routes.dashboard'))

            flash('Usuario o contraseña incorrectos', 'danger')

        except Exception as e:
            # Puedes loguear el error si quieres: print(e) o usar logging
            flash(f'Ocurrió un error al intentar iniciar sesión: {str(e)}', 'danger')

    return render_template('login.html')


# RUTA: Dashboard
@routes.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('routes.login'))

    total = mongo.db.asistentes.count_documents({})
    registrados = mongo.db.asistentes.count_documents({'checked_in': True})
    pendientes = total - registrados
    porcentaje = round((registrados / total * 100), 2) if total else 0
    casos_especiales = mongo.db.casos.count_documents({})
    return render_template(
        'dashboard.html',
        total=total,
        registrados=registrados,
        pendientes=pendientes,
        porcentaje=porcentaje,
        casos_especiales=casos_especiales
    )



# RUTA: Logout
@routes.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('routes.login'))

# RUTA: Subida de CSV con asistentes
import uuid

@routes.route('/cargar_asistentes', methods=['GET', 'POST'])
@rol_requerido('admin')
def cargar_asistentes():
    if 'user_id' not in session:
        return redirect(url_for('routes.login'))

    if request.method == 'POST':
        archivo = request.files['archivo']
        event_id = '2864'

        if not event_id:
            flash('Debes proporcionar el ID del evento.')
            return redirect(url_for('routes.cargar_asistentes'))

        if archivo and archivo.filename.endswith('.csv'):
            ruta = os.path.join(app.config['UPLOAD_FOLDER'], archivo.filename)
            archivo.save(ruta)

            try:
                df = pd.read_csv(ruta)

                columnas_requeridas = {'nombre', 'correo'}
                if not columnas_requeridas.issubset(set(df.columns)):
                    flash('El archivo debe contener las columnas: nombre, correo')
                    return redirect(url_for('routes.cargar_asistentes'))

                insertados = 0
                duplicados = 0

                for i, row in df.iterrows():
                    nombre = str(row.get('nombre', '')).strip()
                    correo = str(row.get('correo', '')).strip()
                    ticket_id = str(row.get('ticket_id', '')).strip()
                    if not nombre or not correo:
                        continue

                    
                    security_code = '720a23f39c'

                    existente = mongo.db.asistentes.find_one({
                        'ticket_id': ticket_id,
                        'event_id': event_id
                    })

                    if existente:
                        duplicados += 1
                        continue

                    asistente = {
                        'nombre': nombre,
                        'correo': correo,
                        'ticket_id': ticket_id,
                        'security_code': security_code,
                        'event_id': event_id,
                        'checked_in': False,
                        'timestamp_checkin': None
                    }

                    mongo.db.asistentes.insert_one(asistente)
                    insertados += 1

                flash(f'Archivo procesado. Agregados: {insertados}. Duplicados ignorados: {duplicados}.')
                return redirect(url_for('routes.dashboard'))

            except Exception as e:
                flash(f'Error al procesar el archivo: {str(e)}')
                return redirect(url_for('routes.cargar_asistentes'))

    return render_template('cargar_asistentes.html')



@routes.route('/asistentes')
@rol_requerido('admin')
def ver_asistentes():
    if 'user_id' not in session:
        return redirect(url_for('routes.login'))

    asistentes = list(mongo.db.asistentes.find())
    return render_template('asistentes.html', asistentes=asistentes)

from datetime import datetime

from urllib.parse import urlparse, parse_qs

@routes.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if 'user_id' not in session:
        return redirect(url_for('routes.login'))

    asistente = None
    mensaje = None
    resultados = []
    query = None

    if request.method == 'POST':
        if 'codigo_qr' in request.form:
            from urllib.parse import urlparse, parse_qs
            qr_data = request.form.get('codigo_qr', '').strip()

            try:
                parsed_url = urlparse(qr_data)
                query_params = parse_qs(parsed_url.query)

                ticket_id = query_params.get('ticket_id', [None])[0]
                event_id = query_params.get('event_id', [None])[0]
                security_code = query_params.get('security_code', [None])[0]

                if ticket_id and event_id and security_code:
                    asistente = mongo.db.asistentes.find_one({
                        'ticket_id': ticket_id,
                        'event_id': event_id,
                        'security_code': security_code
                    })

                    if asistente:
                        if asistente.get('checked_in'):
                            mensaje = f'⚠️ Atención asistente ya fe registrado el {asistente.get("timestamp_checkin").strftime('%d/%m/%Y %H:%M:%S')}'
                        else:
                            mongo.db.asistentes.update_one(
                                {'_id': asistente['_id']},
                                {'$set': {
                                    'checked_in': True,
                                    'timestamp_checkin': datetime.utcnow(),
                                    'registrado_por': session.get('username', 'desconocido')
                                }}
                            )
                            asistente['checked_in'] = True
                            mensaje = '✅ Asistente registrado exitosamente.'
                    else:
                        mensaje = '❌ No se encontró al asistente con ese QR.'
                else:
                    mensaje = '❌ QR incompleto.'
            except Exception as e:
                mensaje = f'Error al leer QR: {str(e)}'

        elif 'busqueda' in request.form:
            
            query = request.form.get('busqueda', '').strip()
            if query:
                resultados = list(mongo.db.asistentes.find({
                    '$or': [
                        {'nombre': {'$regex': query, '$options': 'i'}},
                        {'correo': {'$regex': query, '$options': 'i'}},
                        {'ticket_id': query}
                    ]
                }))
                print(resultados)
    return render_template('checkout.html', asistente=asistente, mensaje=mensaje,
                           resultados=resultados, query=query)


@routes.route('/checkin_manual', methods=['GET', 'POST'])
def checkin_manual():
    if 'user_id' not in session:
        return redirect(url_for('routes.login'))

    asistentes = []
    query = None

    if request.method == 'POST':
        query = request.form.get('busqueda', '').strip()
        print(query)
        if query:
            asistentes = list(mongo.db.asistentes.find({
                '$or': [
                    {'nombre': {'$regex': query, '$options': 'i'}},
                    {'correo': {'$regex': query, '$options': 'i'}},
                    {'ticket_id': query}
                ]
            }))
    print(asistentes)
    return render_template('asistentes.html', asistentes=asistentes, query=query)
    
@routes.route('/checkin_manual/<id>', methods=['POST'])
def confirmar_checkin_manual(id):
    if 'user_id' not in session:
        return redirect(url_for('routes.login'))
    
    mensaje = None

    asistente = mongo.db.asistentes.find_one({'_id': ObjectId(id)})

    if asistente:
        if asistente.get('checked_in'):
            mensaje = f'⚠️ Atención asistente ya fe registrado el {asistente.get("timestamp_checkin").strftime('%d/%m/%Y %H:%M:%S')}'
        else:
            mongo.db.asistentes.update_one(
                {'_id': ObjectId(id)},
                {'$set': {
                    'checked_in': True,
                    'timestamp_checkin': datetime.utcnow(),
                    'registrado_por': session.get('username', 'desconocido')
                }}
            )
            mensaje = '✅ Asistente registrado exitosamente.'
    else:
        mensaje = '❌ El asistente ya estaba registrado o no se encontró.'

    return render_template('checkout.html', asistente=asistente, mensaje=mensaje)
                           

@routes.route('/confirmar_checkin/<id>', methods=['POST'])
def confirmar_checkin(id):
    if 'user_id' not in session:
        return redirect(url_for('routes.login'))
   
    asistente = None
    mensaje = None
    asistente = mongo.db.asistentes.find_one({'_id': ObjectId(id)})

    if asistente:
        if asistente.get('checked_in'):
            mensaje = f'⚠️ Atención asistente ya fe registrado el {asistente.get("timestamp_checkin").strftime('%d/%m/%Y %H:%M:%S')}'
        else:
            mongo.db.asistentes.update_one(
                {'_id': ObjectId(id)},
                {'$set': {
                    'checked_in': True,
                    'timestamp_checkin': datetime.utcnow(),
                    'registrado_por': session.get('username', 'desconocido')
                }}
            )
            asistente['checked_in'] = True
            mensaje = '✅ Asistente registrado exitosamente.'
    else:
        mensaje = '❌ El asistente ya estaba registrado o no se encontró.'

    print(mensaje)
    return render_template('checkout.html', asistente=asistente, mensaje=mensaje)


# Inicializar Firebase una sola vez
if not firebase_admin._apps:
    cred = credentials.Certificate("firebase-key.json")
    firebase_admin.initialize_app(cred)


@routes.route('/casos-especiales', methods=['GET', 'POST'])
def casos_especiales():
    if 'user_id' not in session:
        return redirect(url_for('routes.login'))

    casos = list(mongo.db.casos_especiales.find().sort('registrado_en', -1))
    autorizadores = list(mongo.db.usuarios.find({"autoriza": 1}))

    if request.method == 'POST':
        form = request.form
        nuevo_caso = {
            "nombre": form['nombre'],
            "autorizado_por": form['autorizado_por'],
            "descripcion": form['descripcion'],
            "ticket_id": form.get('ticket_id') or None,
            "codigo_autorizacion": form.get('codigo_autorizacion') or None,
            "estado": "solicitado",
            "registrado_en": datetime.utcnow()
        }

        try:
            mongo.db.casos_especiales.insert_one(nuevo_caso)
            flash('Caso especial registrado correctamente.', 'success')
            notificar_autorizador(form['autorizado_por'], nuevo_caso)
        except Exception as e:
            flash(f'Error al registrar el caso: {e}', 'danger')

        return redirect(url_for('routes.casos_especiales'))

    return render_template('casos_especiales.html', casos=casos, autorizadores=autorizadores)



# Nueva función de notificación con Firebase Admin SDK
def notificar_autorizador(nombre_autorizador, caso_data):
    usuario = mongo.db.usuarios.find_one({
        'username': nombre_autorizador,
        'autoriza': 1
    })
    print(usuario)
    if usuario and usuario.get('token_fcm'):
        mensaje = f"Nuevo caso especial para autorizar:\nAsistente: {caso_data['nombre']}\nMotivo: {caso_data['descripcion']}"

        try:
            message = messaging.Message(
                notification=messaging.Notification(
                    title="Solicitud de Autorización",
                    body=mensaje
                ),
                token=usuario['fcm_token'],
                data={
                    'tipo': 'caso_especial',
                    'ticket_id': caso_data.get('ticket_id', ''),
                    'codigo_autorizacion': caso_data.get('codigo_autorizacion', ''),
                    'nombre': caso_data['nombre']
                }
            )
            response = messaging.send(message)
            print("Mensaje enviado correctamente:", response)
        except Exception as e:
            print("Error al enviar la notificación:", e)


@routes.route('/guardar_token', methods=['POST'])
def guardar_token():
    print('entra')
    if 'user_id' not in session:
        return jsonify({'error': 'Usuario no autenticado'}), 401

    data = request.get_json()
    token = data.get('currentToken')
    print(token)
    if token:
        result = mongo.db.usuarios.update_one(
            {'_id': ObjectId(session['user_id'])},
            {'$set': {'token_fcm': token}}
        )
        return jsonify({'mensaje': 'Token guardado', 'modificado': result.modified_count})
    else:
        return jsonify({'error': 'Token inválido'}), 400

@routes.route('/autorizar', methods=['GET', 'POST'])
def autorizar():
    if 'user_id' not in session:
        return redirect(url_for('routes.login'))

    usuario_actual = mongo.db.usuarios.find_one({'_id': ObjectId(session['user_id'])})

    # Verifica que sea autorizador
    if not usuario_actual or not usuario_actual.get('autoriza'):
        flash("No tienes permisos para acceder a esta página", "danger")
        return redirect(url_for('routes.dashboard'))

    if request.method == 'POST':
        caso_id = request.form.get('caso_id')
        accion = request.form.get('accion')

        if caso_id and accion in ['autorizado', 'rechazado']:
            mongo.db.casos_especiales.update_one(
                {'_id': ObjectId(caso_id)},
                {
                    '$set': {
                        'estado': accion,
                        'autorizado_por': usuario_actual.get('nombre'),
                        'autorizado_en': datetime.utcnow()
                    }
                }
            )
            flash(f'Caso {accion} correctamente.', 'success')
            return redirect(url_for('routes.autorizar'))

    casos_pendientes = list(mongo.db.casos_especiales.find({'estado': 'solicitado'}))

    return render_template('autorizar.html', casos=casos_pendientes, usuario=usuario_actual)

@routes.route('/log-front', methods=['POST'])
def log_front():
    data = request.json
    mensaje = data.get('mensaje')
    nivel = data.get('nivel', 'info')

    if mensaje:
        if nivel == 'error':
            logging.error(f"[JS] {mensaje}")
        elif nivel == 'warning':
            logging.warning(f"[JS] {mensaje}")
        else:
            logging.info(f"[JS] {mensaje}")
        return jsonify({"status": "ok"}), 200
    return jsonify({"status": "missing message"}), 400