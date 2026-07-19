from flask import Blueprint, render_template, redirect, url_for, request, session, flash, jsonify, sessions,current_app
from flask_login import LoginManager
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from datetime import datetime
import pytz
from werkzeug.utils import secure_filename

from datetime import datetime
import firebase_admin
from firebase_admin import credentials, messaging
import pandas as pd
import os
import uuid
import pandas as pd
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

def gt_time(fecha_utc):
    """
    Convierte un datetime en UTC a hora local de Guatemala con formato legible.

    :param timestamp_utc: objeto datetime con tzinfo UTC (como viene de Mongo)
    :return: string en formato 'dd/mm/yyyy HH:MM AM/PM' en hora de Guatemala
    """
    if not fecha_utc:
        return 'Sin registro'

    if isinstance(fecha_utc, str):
        fecha_utc = datetime.fromisoformat(fecha_utc)

    # Convertir a zona UTC si aún no tiene zona
    if fecha_utc.tzinfo is None:
        fecha_utc = fecha_utc.replace(tzinfo=pytz.utc)

    # Convertir a zona horaria de Guatemala
    tz_guatemala = pytz.timezone('America/Guatemala')
    fecha_gt = fecha_utc.astimezone(tz_guatemala)

    
    return fecha_gt.strftime('%d/%m/%Y %I:%M %p')

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

def acceso_requerido(f):
    @wraps(f)
    def decorada(*args, **kwargs):
        if session.get('acceso') != 1:
            flash('Acceso deshabilitado. Contacta al administrador.', 'danger')
            return redirect(url_for('routes.login'))  # o a donde prefieras
        return f(*args, **kwargs)
    return decorada

# MODELO DE USUARIO
class Usuario:
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.nombre = user_data['nombre']
        self.autoriza = user_data['autoriza']
        self.password_hash = user_data['password']
        self.rol = user_data.get('rol', 'staff')  # Por defecto, 'staff'
        self.acceso =  user_data.get('acceso', 0)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return self.id

    @staticmethod
    def get(user_id):
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
@acceso_requerido
@rol_requerido('admin')
def registro():
    if request.method == 'POST':
        nombre=request.form['name']
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        rol = request.form.get('rol', 'staff')  
        autoriza = 0
        token_fcm = ''
        mongo.db.usuarios.insert_one({'username': username,'nombre':nombre, 'password': password, 'rol': rol,'token_fcm':token_fcm,'autoriza':autoriza})
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
                session['autoriza'] = usuario.autoriza
                session['acceso'] = usuario.acceso
                session['nombre'] = usuario.nombre
                return redirect(url_for('routes.dashboard'))

            flash('Usuario o contraseña incorrectos', 'danger')

        except Exception as e:
            # Puedes loguear el error si quieres: print(e) o usar logging
            flash(f'Ocurrió un error al intentar iniciar sesión: {str(e)}', 'danger')

    return render_template('login.html')


# RUTA: Dashboard
@routes.route('/dashboard')
@acceso_requerido
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('routes.login'))

    total = mongo.db.asistentes.count_documents({})
    registrados = mongo.db.asistentes.count_documents({'checked_in': True})
    pre = mongo.db.asistentes.count_documents({'pre_registro': True})
    pre_check = mongo.db.asistentes.count_documents({
    'pre_registro': True,
    'checked_in': True})
    pre = pre - pre_check
    pendientes = total - registrados 
    pendientes_sin_pre = pendientes - pre
    porcentaje = round(((registrados ) / total * 100), 2) if total else 0
    casos_especiales = mongo.db.casos_especiales.count_documents({})

    tipo = request.args.get('boleto', 'todos')
    sexo = request.args.get('sexo', 'todos')

    filtro = {}
    if tipo != 'todos': 
        filtro['boleto'] = tipo
    if sexo != 'todos':
        filtro['sexo'] = sexo

    asistentes = list(mongo.db.asistentes.find(filtro, {'edad': 1}))

    def obtener_edad(asistente):
        try:
            return int(asistente.get('edad', 0))
        except (ValueError, TypeError):
            return 0
    segmento_12_14 = sum(1 for a in asistentes if obtener_edad(a) <= 14)
    segmento_15_17 = sum(1 for a in asistentes if 15 <= obtener_edad(a) <= 17)
    segmento_18_24 = sum(1 for a in asistentes if 18 <= obtener_edad(a) <= 24)
    segmento_25_mas = sum(1 for a in asistentes if obtener_edad(a) >= 25)

    datos_segmentos = {
        "labels": ["12-14","15-17 años", "18-24 años", "25-30+ años"],
        "valores": [segmento_12_14,segmento_15_17, segmento_18_24, segmento_25_mas]
    }


    return render_template(
        'dashboard.html',
        datos_segmentos=datos_segmentos, 
        filtro_tipo=tipo, 
        filtro_sexo=sexo,
        total=total,
        registrados=registrados,
        preregistro=pre,
        pendientes=pendientes,
        porcentaje=porcentaje,
        casos_especiales=casos_especiales,
        pendientes_sin_pre = pendientes_sin_pre
    )



# RUTA: Logout
@routes.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('routes.login'))

# RUTA: Subida de CSV con asistentes


@routes.route('/cargar-asistentes', methods=['GET', 'POST'])
@rol_requerido('admin')
def cargar_asistentes():
    if 'user_id' not in session:
        return redirect(url_for('routes.login'))

    if request.method == 'POST':
        archivo = request.files.get('archivo')
        if archivo and archivo.filename.lower().endswith(('.xlsx', '.xls')):
            try:
                # Leer todo como texto evita que los tickets numéricos terminen en ".0"
                # y que las celdas vacías se guarden como "nan".
                df = pd.read_excel(archivo, dtype=str, keep_default_na=False)
                df.columns = [str(columna).strip() for columna in df.columns]

                columnas_requeridas = {
                    "Código de barras",
                    "Nombre del asistente",
                    "Boleto del evento"
                }
                columnas_faltantes = columnas_requeridas.difference(df.columns)
                if columnas_faltantes:
                    faltantes = ", ".join(sorted(columnas_faltantes))
                    flash(f'Faltan columnas obligatorias en el Excel: {faltantes}.', 'danger')
                    return render_template('cargar_asistentes.html')

                def valor(fila, *columnas):
                    """Obtiene el primer encabezado disponible, nuevo o anterior."""
                    for columna in columnas:
                        if columna in df.columns:
                            return str(fila.get(columna, '')).strip()
                    return ''

                insertados = 0
                duplicados = 0

                for _, fila in df.iterrows():
                    ticket_id = valor(fila, "Código de barras")

                    if not ticket_id:
                        continue  # omitir filas vacías

                    # Verifica duplicado
                    if mongo.db.asistentes.find_one({"ticket_id": ticket_id}):
                        duplicados += 1
                        continue

                    boleto_raw = valor(fila, "Boleto del evento")
                    if "voluntario" in boleto_raw.lower():
                        boleto = boleto_raw  # conserva el valor original si es voluntario
                    elif "Training Días: 25, 26, 27" in boleto_raw:
                        boleto = "Completo"
                    else:
                        boleto = "Basico"

                    asistente = {
                        "ticket_id": ticket_id,
                        "nombre": valor(fila, "Nombre del asistente"),
                        "telefono": valor(fila, "Teléfono"),
                        "correo": valor(fila, "Correo electrónico"),
                        "boleto": boleto,
                        "nombre_completo": valor(fila, "Nombre", "Nombre Completo"),
                        "sexo": valor(fila, "Sexo"),
                        "edad": valor(fila, "Edad", "Edad Actual"),
                        "etapa_somosjovenes": valor(
                            fila,
                            "Etapa en la que sirve",
                            "¿A qué etapa de Somos.Jóvenes pertenece?"
                        ),
                        "area": valor(fila, "Area", "Área"),
                        "talla": valor(fila, "Talla de playera", "Talla"),

                        # Campos adicionales que pueden seguir llegando en el Excel.
                        "miembro_iglesia": valor(fila, "¿Es miembro de Iglesia VidaReal.tv?"),
                        "primera_vez": valor(fila, "¿Es su primera vez asistiendo a la conferencia?"),
                        "telefono_whatsapp": valor(fila, "Teléfono (WhatsApp)"),
                        "punto_vidareal": valor(fila, "Si respondió “sí”, ¿a qué Punto VidaReal asiste?"),
                        "almuerzo": valor(fila, "Almuerzo"),
                        "training": valor(fila, "Training")
                    }

                    mongo.db.asistentes.insert_one(asistente)
                    insertados += 1

                flash(f'{insertados} asistentes cargados. {duplicados} duplicados omitidos.', 'success')
            except Exception as e:
                flash(f'Error al procesar el archivo: {e}', 'danger')
        else:
            flash('Por favor sube un archivo Excel (.xlsx)', 'warning')

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
@acceso_requerido
def checkout():
    if 'user_id' not in session:
        return redirect(url_for('routes.login'))

    asistente = None
    mensaje = None
    resultados = []
    query = None

    if request.method == 'POST':
        if 'codigo_qr' in request.form:
            qr_data = request.form.get('codigo_qr', '').strip()

            try:
                ticket_id = qr_data  # QR contiene directamente el código

                if ticket_id:
                    asistente = mongo.db.asistentes.find_one({'ticket_id': ticket_id})

                    if asistente:
                        if asistente.get('checked_in'):
                            mensaje = f'⚠️ Atención: asistente ya fue registrado el { gt_time(asistente.get("timestamp_checkin"))}'
                        else:
                            mongo.db.asistentes.update_one(
                                {'_id': asistente['_id']},
                                {'$set': {
                                    'checked_in': True,
                                    'timestamp_checkin': datetime.now(pytz.timezone('America/Guatemala')),
                                    'registrado_por': session.get('username', 'desconocido'),
                                    'recogio_almuerzo' : True
                                        # 'pre_registro': True,
                                        # 'timestamp_pre': datetime.now(pytz.timezone('America/Guatemala')),
                                        # 'pre_registrado_por': session.get('username', 'desconocido')
                                    
                                }}
                            )
                            asistente['checked_in'] = True
                            mensaje = '✅ Asistente registrado exitosamente.'
                    else:
                        mensaje = '❌ No se encontró al asistente con ese código.'
                else:
                    mensaje = '❌ Código QR vacío.'
            except Exception as e:
                mensaje = f'Error al procesar el código: {str(e)}'

        elif 'busqueda' in request.form:
            query = request.form.get('busqueda', '').strip()
            if query:
                resultados = list(mongo.db.asistentes.find({
                '$or': [
                    {'nombre': {'$regex': query, '$options': 'i'}},
                    {'correo': {'$regex': query, '$options': 'i'}},
                    {'nombre_completo': {'$regex': query, '$options': 'i'}},
                    {'ticket_id': query}
                ]
                }))
    return render_template('checkout.html', asistente=asistente, mensaje=mensaje,
                           resultados=resultados, query=query)


@routes.route('/checkin_manual', methods=['GET', 'POST'])
@acceso_requerido
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
                    {'nombre_completo': {'$regex': query, '$options': 'i'}},
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
            mensaje = f'⚠️ Atención asistente ya fe registrado el {gt_time(asistente.get("timestamp_checkin"))}'
        else:
            mongo.db.asistentes.update_one(
                {'_id': ObjectId(id)},
                {'$set': {
                    'checked_in': True,
                    'timestamp_checkin': datetime.now(pytz.timezone('America/Guatemala')),
                    'registrado_por': session.get('username', 'desconocido')
                    # 'pre_registro': True,
                    # 'timestamp_pre': datetime.now(pytz.timezone('America/Guatemala')),
                    # 'pre_registrado_por': session.get('username', 'desconocido')
                }}
            )
            mensaje = '✅ Asistente registrado exitosamente.'
    else:
        mensaje = '❌ El asistente ya estaba registrado o no se encontró.'

    return render_template('checkout.html', asistente=asistente, mensaje=mensaje)
                           

@routes.route('/confirmar_checkin/<id>', methods=['POST'])
@acceso_requerido
def confirmar_checkin(id):
    if 'user_id' not in session:
        return redirect(url_for('routes.login'))
   
    asistente = None
    mensaje = None
    asistente = mongo.db.asistentes.find_one({'_id': ObjectId(id)})

    if asistente:
        if asistente.get('checked_in'):
            mensaje = f'⚠️ Atención asistente ya fue registrado el {gt_time(asistente.get("timestamp_checkin"))}'
        else:
            mongo.db.asistentes.update_one(
                {'_id': ObjectId(id)},
                {'$set': {
                    'checked_in': True,
                    'timestamp_checkin': datetime.now(pytz.timezone('America/Guatemala')),
                    'registrado_por': session.get('username', 'desconocido')
                    # 'pre_registro': True,
                    # 'timestamp_pre': datetime.now(pytz.timezone('America/Guatemala')),
                    # 'pre_registrado_por': session.get('username', 'desconocido')
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
        print("Llamada a guardar el caso")
        form = request.form
        nuevo_caso = {
            "nombre": form['nombre'],
            "autorizado_por": form['autorizado_por'],
            "descripcion": form['descripcion'],
            "ticket_id": form.get('ticket_id') or None,
            "codigo_autorizacion": form.get('codigo_autorizacion') or None,
            "estado": "solicitado",
            "registrado_en": datetime.now(pytz.timezone('America/Guatemala')),
            "autorizado_en" : ''
        }

        try:
            mongo.db.casos_especiales.insert_one(nuevo_caso)
            flash('Caso especial registrado correctamente.', 'success')
            notificar_autorizador(form['autorizado_por'], nuevo_caso)
        except Exception as e:
            flash(f'Error al registrar el caso: {e}', 'danger')


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
        print(mensaje)
        try:
            message = messaging.Message(
                notification=messaging.Notification(
                    title="Solicitud de Autorización",
                    body=mensaje
                ),
                token=usuario['token_fcm'],
                data={
                    'tipo': 'caso_especial',
                    'ticket_id': str(caso_data.get('ticket_id') or ''),
                    'codigo_autorizacion': str(caso_data.get('codigo_autorizacion') or ''),
                    'nombre': str(caso_data.get('nombre') or '')
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
    print(request.method)
    # Verifica que sea autorizador
    if not usuario_actual or not usuario_actual.get('autoriza'):
        flash("No tienes permisos para acceder a esta página", "danger")
        return redirect(url_for('routes.dashboard'))
    
    if request.method == 'POST':
        caso_id = request.form.get('caso_id')
        accion = request.form.get('accion')
       
       
        request.form.get('id')
        if caso_id and accion in ['autorizado', 'rechazado']:
            mongo.db.casos_especiales.update_one(
                {'_id': ObjectId(caso_id)},
                {
                    '$set': {
                        'estado': accion,
                        'autorizado_por': usuario_actual.get('nombre'),
                        'autorizado_en': datetime.now(pytz.timezone('America/Guatemala'))
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

@routes.route('/ver-caso/<caso_id>', methods=['GET', 'POST'])
def ver_caso(caso_id):
    if 'user_id' not in session:
        return redirect(url_for('routes.login'))

    caso = mongo.db.casos_especiales.find_one({"_id": ObjectId(caso_id)})

    if not caso:
        flash("Caso no encontrado", "danger")
        return redirect(url_for('routes.autorizaciones'))

    if request.method == 'POST':
        accion = request.form.get('accion')
        if accion == 'aprobar':
            mongo.db.casos_especiales.update_one(
                {"_id": ObjectId(caso_id)},
                {"$set": {"estado": "Autorizado",
                'autorizado_en': datetime.now(pytz.timezone('America/Guatemala'))}
                }
            )
            flash("Caso aprobado correctamente", "success")
        elif accion == 'rechazar':
            mongo.db.casos_especiales.update_one(
                {"_id": ObjectId(caso_id)},
               {"$set": {"estado": "Rechazado",
                'autorizado_en': datetime.now(pytz.timezone('America/Guatemala'))}
                }
            )
            flash("Caso rechazado", "warning")
        return redirect(url_for('routes.autorizar'))

    return render_template("ver_caso.html", caso=caso)
