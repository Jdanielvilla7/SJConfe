from flask import Blueprint, render_template, redirect, url_for, request, session, flash, jsonify, sessions, current_app, send_file
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
import smtplib
import uuid
import pandas as pd
from extensions import mongo, app
from functools import wraps
from io import BytesIO
from flask import abort
import logging
from email.message import EmailMessage
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from reportlab.graphics.barcode import code128
import qrcode

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

def token_bearer_requerido(f):
    """Decorador para validar Bearer Token en requests API"""
    @wraps(f)
    def decorada(*args, **kwargs):
        # Obtener token del header Authorization
        auth_header = request.headers.get('Authorization', '')
        
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Autenticación requerida. Usar: Authorization: Bearer <token>'}), 401
        
        token_recibido = auth_header[7:]  # Elimina "Bearer "
        token_esperado = os.getenv('API_TOKEN', 'ads5Kl6dK_4iZ-4kYbpChMH3AtGsIyW1egNqbOC6gqo')
        
        if token_recibido != token_esperado:
            return jsonify({'error': 'Token inválido o expirado'}), 403
        
        return f(*args, **kwargs)
    return decorada


TICKET_PAGE_WIDTH = 595.0
TICKET_PAGE_HEIGHT = 842.0
TICKET_GRID_STEP = 50

TICKET_BORDER = {
    'x0': 17.25,
    'y0': 30.00,
    'x1': 577.50,
    'y1': 271.50
}

TICKET_SEPARATOR = {
    'x': 474.75,
    'y0': 39.75,
    'y1': 261.75
}

# Adjust these coordinates after reviewing the grid overlay.
TICKET_FIELD_COORDS = {
    'evento_fecha_hora': {'x': 32.25, 'y_listado': 58.59, 'font': 'Helvetica-Bold', 'size': 10},
    'evento_nombre': {'x': 32.25, 'y_listado': 87.93, 'font': 'Helvetica-Bold', 'size': 20},
    'evento_direccion': {'x': 32.25, 'y_listado': 129.09, 'font': 'Helvetica', 'size': 10},
    'evento_pais': {'x': 32.25, 'y_listado': 147.09, 'font': 'Helvetica', 'size': 10, 'color': (0.5, 0.5, 0.5)},
    'nombre_cliente': {'x': 32.25, 'y_listado': 176.17, 'font': 'Helvetica', 'size': 12},
    'evento_footer': {
        'x_center': 297.385,
        'y_listado': 827.65,
        'font': 'Helvetica',
        'size': 8,
        'align': 'center'
    },
}

TICKET_QR_COORDS = {'x': 481.50, 'y_listado_bottom': 125.25, 'size': 87}
TICKET_BARCODE_COORDS = {
    'x': 492.00,
    'y_listado_bottom': 252.75,
    'width': 63,
    'height': 126
}


def _draw_grid(canvas_obj, width, height, step):
    canvas_obj.setStrokeColorRGB(0.85, 0.85, 0.85)
    canvas_obj.setFont('Helvetica', 6)

    for x in range(0, int(width) + 1, step):
        canvas_obj.line(x, 0, x, height)
        canvas_obj.drawString(x + 2, 2, str(x))

    for y in range(0, int(height) + 1, step):
        canvas_obj.line(0, y, width, y)
        canvas_obj.drawString(2, y + 2, str(y))


def _to_rl_y(y_listado, height=TICKET_PAGE_HEIGHT):
    return height - y_listado


def _rect_from_listado(x0, y0, x1, y1):
    y_top = _to_rl_y(y0)
    y_bottom = _to_rl_y(y1)
    return x0, y_bottom, x1 - x0, y_top - y_bottom


def _draw_ticket_frame(canvas_obj):
    x, y, width, height = _rect_from_listado(
        TICKET_BORDER['x0'],
        TICKET_BORDER['y0'],
        TICKET_BORDER['x1'],
        TICKET_BORDER['y1']
    )

    canvas_obj.setStrokeColorRGB(0, 0, 0)
    canvas_obj.setLineWidth(1)
    canvas_obj.rect(x, y, width, height, stroke=1, fill=0)

    line_y0 = _to_rl_y(TICKET_SEPARATOR['y0'])
    line_y1 = _to_rl_y(TICKET_SEPARATOR['y1'])
    canvas_obj.setDash(2, 2)
    canvas_obj.line(TICKET_SEPARATOR['x'], line_y0, TICKET_SEPARATOR['x'], line_y1)
    canvas_obj.setDash()


def _build_qr_image(ticket_id):
    qr = qrcode.QRCode(
        version=2,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=6,
        border=2
    )
    qr.add_data(ticket_id)
    qr.make(fit=True)
    return qr.make_image(fill_color='black', back_color='white')


def _draw_barcode(canvas_obj, ticket_id, box_x, box_y, box_width, box_height):
    barcode = code128.Code128(ticket_id, barHeight=box_width, barWidth=1)
    target_width = box_height
    target_height = box_width

    scale_x = target_width / barcode.width
    scale_y = target_height / barcode.height
    scale = min(scale_x, scale_y)

    offset_x = (target_width - barcode.width * scale) / 2
    offset_y = (target_height - barcode.height * scale) / 2

    canvas_obj.saveState()
    canvas_obj.translate(box_x, box_y + box_height)
    canvas_obj.rotate(-90)
    canvas_obj.scale(scale, scale)
    barcode.drawOn(canvas_obj, offset_x, offset_y)
    canvas_obj.restoreState()


def generate_ticket_pdf_bytes(
    nombre_cliente,
    evento_nombre,
    evento_direccion,
    evento_fecha_hora,
    ticket_id,
    evento_pais=None,
    evento_footer=None,
    debug_grid=False
):
    packet = BytesIO()
    canvas_obj = canvas.Canvas(packet, pagesize=(TICKET_PAGE_WIDTH, TICKET_PAGE_HEIGHT))

    if debug_grid:
        _draw_grid(canvas_obj, TICKET_PAGE_WIDTH, TICKET_PAGE_HEIGHT, TICKET_GRID_STEP)

    _draw_ticket_frame(canvas_obj)

    fields = {
        'evento_fecha_hora': evento_fecha_hora,
        'evento_nombre': evento_nombre,
        'evento_direccion': evento_direccion,
        'evento_pais': evento_pais,
        'nombre_cliente': nombre_cliente,
        'evento_footer': evento_footer
    }

    for key, value in fields.items():
        if not value:
            continue
        config = TICKET_FIELD_COORDS.get(key)
        if not config:
            continue
        canvas_obj.setFont(config['font'], config['size'])
        color = config.get('color')
        if color:
            canvas_obj.setFillColorRGB(*color)
        else:
            canvas_obj.setFillColorRGB(0, 0, 0)

        y = _to_rl_y(config['y_listado'])
        if config.get('align') == 'center':
            canvas_obj.drawCentredString(config['x_center'], y, str(value))
        else:
            canvas_obj.drawString(config['x'], y, str(value))

    qr_image = _build_qr_image(ticket_id)
    qr_buffer = BytesIO()
    qr_image.save(qr_buffer, format='PNG')
    qr_buffer.seek(0)
    qr_reader = ImageReader(qr_buffer)

    qr_y = _to_rl_y(TICKET_QR_COORDS['y_listado_bottom'])
    canvas_obj.drawImage(
        qr_reader,
        TICKET_QR_COORDS['x'],
        qr_y,
        width=TICKET_QR_COORDS['size'],
        height=TICKET_QR_COORDS['size'],
        mask='auto'
    )

    barcode_y = _to_rl_y(TICKET_BARCODE_COORDS['y_listado_bottom'])
    _draw_barcode(
        canvas_obj,
        ticket_id,
        TICKET_BARCODE_COORDS['x'],
        barcode_y,
        TICKET_BARCODE_COORDS['width'],
        TICKET_BARCODE_COORDS['height']
    )

    canvas_obj.save()
    packet.seek(0)
    return packet.read()


def generate_template_grid_pdf_bytes():
    packet = BytesIO()
    canvas_obj = canvas.Canvas(packet, pagesize=(TICKET_PAGE_WIDTH, TICKET_PAGE_HEIGHT))
    _draw_grid(canvas_obj, TICKET_PAGE_WIDTH, TICKET_PAGE_HEIGHT, TICKET_GRID_STEP)
    _draw_ticket_frame(canvas_obj)
    canvas_obj.save()
    packet.seek(0)
    return packet.read()


def enviar_ticket_email(destinatario, nombre_cliente, pdf_bytes, ticket_id):
    # smtp_host = os.getenv('SMTP_HOST', 'smtp.gmail.com')
    # smtp_port = int(os.getenv('SMTP_PORT', '587'))
    # smtp_user = os.getenv('SMTP_USER','cursos@institutocrux.org')
    # smtp_password = os.getenv('SMTP_PASSWORD','njdm tisa qhuk jamx')
    # smtp_from = os.getenv('SMTP_FROM', smtp_user)
    smtp_host = 'smtp.gmail.com'
    smtp_port = 587
    smtp_user = 'atejada@institutocrux.org'
    smtp_password = 'njdmtisaqhukjamx'
    smtp_from = 'cursos@institutocrux.org'

    if not smtp_user or not smtp_password:
        raise ValueError('SMTP_USER y SMTP_PASSWORD son requeridos')

    subject = os.getenv('TICKET_EMAIL_SUBJECT', 'Tu ticket para el evento')
    body_template = f"""
    <!DOCTYPE html>
    <html lang="es">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ticket Congreso Cristianamente</title>
    </head>

    <body style="margin:0; padding:0; background-color:#f3f1ee; font-family:Arial, Helvetica, sans-serif; color:#5f5f5f;">

    <!-- Preheader oculto -->
    <div style="display:none; max-height:0; overflow:hidden; opacity:0; color:transparent;">
        Tu ticket para el Congreso Cristianamente está adjunto en este correo.
    </div>

    <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f3f1ee; padding:32px 12px;">
        <tr>
        <td align="center">

            <table width="100%" cellpadding="0" cellspacing="0" style="max-width:620px; background-color:#ffffff; border-radius:18px; overflow:hidden; box-shadow:0 10px 28px rgba(0,0,0,0.10);">

            <!-- Header -->
            <tr>
                <td style="background-color:#ffffff; padding:34px 32px 24px; text-align:center;">
                <img 
                    src="https://institutocrux.org/wp-content/uploads/2025/06/cropped-LogoWEB-scaled-1-2048x794.png" 
                    alt="Instituto CRUX"
                    width="260"
                    style="display:block; margin:0 auto; max-width:260px; width:100%; height:auto;"
                >
                </td>
            </tr>

            <!-- Banda naranja -->
            <tr>
                <td style="background-color:#f36b16; padding:26px 30px; text-align:center;">
                <h1 style="margin:0; color:#ffffff; font-size:26px; line-height:1.25; font-weight:700;">
                    Congreso Cristianamente
                </h1>
                <p style="margin:8px 0 0; color:#fff3eb; font-size:15px; line-height:1.5;">
                    Tu inscripción ha sido confirmada
                </p>
                </td>
            </tr>

            <!-- Contenido -->
            <tr>
                <td style="padding:36px 34px 28px;">

                <p style="margin:0 0 20px; font-size:17px; line-height:1.7; color:#4b4b4b;">
                    Hola <strong style="color:#f36b16;">{nombre_cliente}</strong>:
                </p>

                <p style="margin:0 0 18px; font-size:16px; line-height:1.7; color:#5f5f5f;">
                    Nos alegra que seas parte del <strong>Congreso Cristianamente</strong>.
                </p>

                <p style="margin:0 0 20px; font-size:16px; line-height:1.7; color:#5f5f5f;">
                    Adjunto encontrarás el ticket correspondiente a tu inscripción. 
                    Presenta el código QR el día del evento para ingresar.
                </p>

                <!-- Caja destacada -->
                <table width="100%" cellpadding="0" cellspacing="0" style="margin:28px 0;">
                    <tr>
                    <td style="background-color:#fff4ed; border-left:5px solid #f36b16; padding:18px 20px; border-radius:12px;">
                        <p style="margin:0; font-size:15px; line-height:1.6; color:#5f5f5f;">
                        <strong style="color:#f36b16;">Importante:</strong>
                        lleva tu ticket disponible en tu celular o impreso para facilitar tu ingreso al evento.
                        </p>
                    </td>
                    </tr>
                </table>

                <p style="margin:0 0 18px; font-size:16px; line-height:1.7; color:#5f5f5f;">
                    Si tienes alguna duda o necesitas apoyo, puedes comunicarte con nosotros al:
                </p>

                <!-- Botón WhatsApp / Teléfono -->
                <table cellpadding="0" cellspacing="0" align="center" style="margin:26px auto 30px;">
                    <tr>
                    <td align="center" style="background-color:#f36b16; border-radius:999px;">
                        <a href="https://wa.me/50235054714" 
                        style="display:inline-block; padding:14px 26px; font-size:15px; font-weight:bold; color:#ffffff; text-decoration:none; border-radius:999px;">
                        +502 3505-4714
                        </a>
                    </td>
                    </tr>
                </table>

                <p style="margin:0 0 6px; font-size:16px; line-height:1.7; color:#5f5f5f;">
                    ¡Te esperamos!
                </p>

                <p style="margin:0; font-size:16px; line-height:1.7; color:#4b4b4b; font-weight:bold;">
                    Instituto CRUX
                </p>

                </td>
            </tr>

            <!-- Footer -->
            <tr>
                <td style="background-color:#6b6762; padding:24px 30px; text-align:center;">
                <p style="margin:0 0 8px; font-size:13px; color:#ffffff; line-height:1.5;">
                    Este correo fue enviado automáticamente como confirmación de tu inscripción.
                </p>
                <p style="margin:0; font-size:13px; color:#dedbd8; line-height:1.5;">
                    © 2026 Instituto CRUX. Todos los derechos reservados.
                </p>
                </td>
            </tr>

            </table>

        </td>
        </tr>
    </table>

    </body>
    </html>
    """
    html_body  = body_template.format(nombre_cliente=nombre_cliente)

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = smtp_from
    msg['To'] = destinatario
    msg.set_content(
    f"Hola {nombre_cliente}, adjunto encontrarás tu ticket para el Congreso Cristianamente.")
    msg.add_alternative(html_body , subtype="html")
    filename = f'ticket_ICRUX.pdf'
    msg.add_attachment(pdf_bytes, maintype='application', subtype='pdf', filename=filename)
    with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(smtp_user, smtp_password)
        server.send_message(msg)

    print("Login Gmail SMTP OK")
    # with smtplib.SMTP(smtp_host, smtp_port) as server:
    #     server.ehlo()
    #     server.starttls()
    #     server.ehlo() 
    #     server.login(smtp_user, smtp_password)
    #     server.send_message(msg)

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
    pendientes = total - registrados 
    pendientes_sin_pre = pendientes
    porcentaje = round(((registrados ) / total * 100), 2) if total else 0
    casos_especiales = mongo.db.casos_especiales.count_documents({})

    cabana = request.args.get('cabana', 'todos')
    lider = request.args.get('lider', 'todos')

    filtro = {}
    if cabana != 'todos': 
        filtro['cabana'] = cabana
    if lider != 'todos':
        filtro['lider'] = lider

    asistentes = list(mongo.db.asistentes.find(filtro, {'edad': 1}))
    cabanas = sorted([item for item in mongo.db.asistentes.distinct('cabana') if item])
    lideres = sorted([item for item in mongo.db.asistentes.distinct('lider') if item])

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
        filtro_cabana=cabana,
        filtro_lider=lider,
        cabanas=cabanas,
        lideres=lideres,
        total=total,
        registrados=registrados,
        preregistro=0,
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
        if archivo and archivo.filename.endswith('.xlsx'):
            try:
                df = pd.read_excel(archivo)
                insertados = 0
                duplicados = 0

                def valor_columna(fila, *columnas):
                    for columna in columnas:
                        valor = fila.get(columna, "")
                        if not pd.isna(valor) and str(valor).strip() != "":
                            return str(valor).strip()
                    return ""

                for _, fila in df.iterrows():
                    ticket_id = valor_columna(fila, "RegistrationID")

                    if not ticket_id:
                        continue  # omitir filas vacías

                    # Verifica duplicado
                    if mongo.db.asistentes.find_one({"ticket_id": ticket_id}):
                        duplicados += 1
                        continue

                    asistente = {
                        "ticket_id": ticket_id,
                        "cabana": valor_columna(fila, "Cabaña", "Cabana"),
                        "nombre": valor_columna(fila, "Nombre"),
                        "lider": valor_columna(fila, "Lider", "Líder"),
                        "correo": valor_columna(fila, "Correo"),
                        "registro": valor_columna(fila, "Registro"),
                        "edad": valor_columna(fila, "Edad"),
                        "telefono": valor_columna(fila, "Telefono", "Teléfono"),
                        "alergias": valor_columna(fila, "alergias", "Alergias"),
                        "alimentos": valor_columna(fila, "alimentos", "Alimentos"),
                        "medicamentos": valor_columna(fila, "medicamentos", "Medicamentos"),
                        "nada": valor_columna(fila, "nada", "Nada")
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


# ENDPOINT API: Registrar asistentes via Bearer Token
@routes.route('/api/asistentes', methods=['POST'])
@token_bearer_requerido
def registrar_asistentes_api():
    """
    Endpoint API para registrar asistentes con autenticación Bearer Token.
    Genera automáticamente el ticket_id para cada asistente, crea el PDF
    del ticket usando Boleto.pdf y lo envía por correo.
    
    Esperado: JSON con estructura:
    {
        "evento": {
            "nombre": "string (requerido)",
            "direccion": "string (requerido)",
            "fecha_hora": "string (requerido)"
        },
        "asistentes": [
            {
                "nombre": "string (requerido)",
                "correo": "string (requerido)",
                "cabana": "string",
                "lider": "string",
                "registro": "string",
                "edad": "string/int",
                "telefono": "string",
                "alergias": "string",
                "alimentos": "string",
                "medicamentos": "string",
                "nada": "string"
            }
        ]
    }
    
    Respuesta: JSON con resultado de inserción e IDs generados
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'JSON vacío'}), 400
        
        asistentes_data = data.get('asistentes', [])
        
        if not asistentes_data:
            return jsonify({'error': 'El campo "asistentes" es requerido y debe ser una lista'}), 400
        
        if not isinstance(asistentes_data, list):
            return jsonify({'error': 'El campo "asistentes" debe ser una lista'}), 400
        
        
        evento_nombre = 'Congreso Cristiana Mente'
        evento_direccion = 'Centro de Convenciones Ilumina z10'
        evento_fecha_hora = '2026-08-01'        
        evento_pais =   'Guatemala'
        evento_footer = 'Instituto CRUX'

        if not evento_nombre or not evento_direccion or not evento_fecha_hora:
            return jsonify({
                'error': 'El objeto "evento" es requerido con nombre, direccion y fecha_hora'
            }), 400

        insertados = 0
        errores = []
        asistentes_registrados = []
        
        for idx, asistente in enumerate(asistentes_data):
            try:
                # Validar nombre (requerido)
                nombre = asistente.get('nombre', '').strip()

                correo = asistente.get('correo', '').strip()
                
                if not nombre:
                    errores.append(f"Registro {idx}: nombre es requerido")
                    continue

                if not correo:
                    errores.append(f"Registro {idx}: correo es requerido")
                    continue
                
                # Generar ticket_id unico
                ticket_id = str(uuid.uuid4())

                pdf_bytes = generate_ticket_pdf_bytes(
                    nombre_cliente=nombre,
                    evento_nombre=evento_nombre,
                    evento_direccion=evento_direccion,
                    evento_fecha_hora=evento_fecha_hora,
                    ticket_id=ticket_id,
                    evento_pais=evento_pais,
                    evento_footer=evento_footer
                )
                
                # Construir documento del asistente
                nuevo_asistente = {
                    'ticket_id': ticket_id,
                    'nombre': nombre,
                    'cabana': asistente.get('cabana', '').strip(),
                    'lider': asistente.get('lider', '').strip(),
                    'correo': correo,
                    'registro': asistente.get('registro', '').strip(),
                    'edad': asistente.get('edad', ''),
                    'telefono': asistente.get('telefono', '').strip(),
                    'alergias': asistente.get('alergias', '').strip(),
                    'alimentos': asistente.get('alimentos', '').strip(),
                    'medicamentos': asistente.get('medicamentos', '').strip(),
                    'nada': asistente.get('nada', '').strip(),
                    'evento': {
                        'nombre': evento_nombre,
                        'direccion': evento_direccion,
                        'fecha_hora': evento_fecha_hora,
                        'pais': evento_pais,
                        'footer': evento_footer
                    },
                    'checked_in': False,
                    'fecha_registro_api': datetime.now(pytz.timezone('America/Guatemala'))
                }

                insert_result = mongo.db.asistentes.insert_one(nuevo_asistente)
                insertados += 1

                email_enviado = True
                email_error = None

                try:
                    enviar_ticket_email(correo, nombre, pdf_bytes, ticket_id)
                except Exception as e:
                    email_enviado = False
                    email_error = str(e)

                update_payload = {
                    'email_enviado': email_enviado,
                    'email_enviado_en': datetime.now(pytz.timezone('America/Guatemala')) if email_enviado else None,
                    'email_error': email_error
                }

                mongo.db.asistentes.update_one(
                    {'_id': insert_result.inserted_id},
                    {'$set': update_payload}
                )

                if not email_enviado:
                    errores.append(f"Registro {idx}: error al enviar correo - {email_error}")
                
                # Agregar a respuesta con ticket_id generado
                asistentes_registrados.append({
                    'nombre': nombre,
                    'ticket_id': ticket_id,
                    'correo': correo,
                    'email_enviado': email_enviado
                })
                
            except Exception as e:
                errores.append(f"Registro {idx}: {str(e)}")
        
        respuesta = {
            'exitoso': True,
            'insertados': insertados,
            'total_procesados': len(asistentes_data),
            'asistentes': asistentes_registrados,
            'errores': errores if errores else None
        }
        
        logging.info(f"API: {insertados} asistentes registrados")
        
        return jsonify(respuesta), 201
    
    except Exception as e:
        logging.error(f"Error en /api/asistentes: {str(e)}")
        return jsonify({'error': f'Error al procesar la solicitud: {str(e)}'}), 500


@routes.route('/api/ticket-template-grid', methods=['GET'])
@token_bearer_requerido
def descargar_template_grid():
    try:
        pdf_bytes = generate_template_grid_pdf_bytes()
        return send_file(
            BytesIO(pdf_bytes),
            mimetype='application/pdf',
            as_attachment=True,
            download_name='Boleto_grid.pdf'
        )
    except Exception as e:
        logging.error(f"Error al generar grid del template: {str(e)}")
        return jsonify({'error': f'No se pudo generar el grid: {str(e)}'}), 500



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
                    {'lider': {'$regex': query, '$options': 'i'}},
                    {'cabana': {'$regex': query, '$options': 'i'}},
                    {'telefono': {'$regex': query, '$options': 'i'}},
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
                    {'lider': {'$regex': query, '$options': 'i'}},
                    {'cabana': {'$regex': query, '$options': 'i'}},
                    {'telefono': {'$regex': query, '$options': 'i'}},
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
