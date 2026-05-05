# ⚙️ Guía de Configuración - Administrador

Esta guía es para el **administrador del sistema** que debe configurar el servidor y proporcionar las credenciales al desarrollador de la landing page.

---

## 📋 Checklist de Configuración

- [ ] Generar token de API
- [ ] Configurar variables de entorno
- [ ] Probar el endpoint
- [ ] Documentar credenciales
- [ ] Entregar documentación al desarrollador

---

## 1️⃣ Generar Token de API

### Opción A: Usar UUID (Recomendado)

#### En Linux/Mac:
```bash
python3 -c "import uuid; print(uuid.uuid4())"
```

#### En PowerShell (Windows):
```powershell
[guid]::NewGuid()
```

#### En Python:
```python
import uuid
token = str(uuid.uuid4())
print(f"Token: {token}")
```

**Ejemplo de salida:**
```
550e8400-e29b-41d4-a716-446655440000
```

---

## 2️⃣ Configurar Variables de Entorno

### En archivo `.env` (Desarrollo):

Crear archivo en la raíz del proyecto:
```
SECRET_KEY=tu_clave_secreta_aqui
MONGO_URI=mongodb://usuario:contraseña@host:puerto/bdnombre
API_TOKEN=550e8400-e29b-41d4-a716-446655440000
```

### En Producción (Heroku, Railway, etc):

**Heroku:**
```bash
heroku config:set API_TOKEN=550e8400-e29b-41d4-a716-446655440000
```

**Railway:**
```bash
railway variables set API_TOKEN=550e8400-e29b-41d4-a716-446655440000
```

**Environment Variables en Dashboard:**
1. Ir a Settings / Configuration
2. Agregar variable: `API_TOKEN = 550e8400-e29b-41d4-a716-446655440000`

---

## 3️⃣ Verificar la Instalación

### Probar el endpoint (cURL):

```bash
curl -X POST http://localhost:5000/api/asistentes \
  -H "Authorization: Bearer 550e8400-e29b-41d4-a716-446655440000" \
  -H "Content-Type: application/json" \
  -d '{
    "asistentes": [
      {
        "nombre": "Juan Test",
        "correo": "juan@test.com"
      }
    ]
  }'
```

**Respuesta esperada (201):**
```json
{
  "exitoso": true,
  "insertados": 1,
  "total_procesados": 1,
  "asistentes": [
    {
      "nombre": "Juan Test",
      "ticket_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
      "correo": "juan@test.com"
    }
  ],
  "errores": null
}
```

---

## 4️⃣ Script de Prueba (Python)

Guardar como `test_api.py`:

```python
import requests
import json
from dotenv import load_dotenv
import os

# Cargar variables de entorno
load_dotenv()

API_TOKEN = os.getenv('API_TOKEN', 'test_token')
API_URL = 'http://localhost:5000/api/asistentes'

def test_endpoint():
    """Prueba básica del endpoint de registro"""
    
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {API_TOKEN}'
    }
    
    payload = {
        'asistentes': [
            {
                'nombre': 'Test User 1',
                'correo': 'test1@example.com',
                'telefono': '1234567890',
                'edad': '25'
            },
            {
                'nombre': 'Test User 2',
                'correo': 'test2@example.com',
                'telefono': '0987654321',
                'edad': '30'
            }
        ]
    }
    
    print("=" * 60)
    print("PRUEBA DE ENDPOINT: POST /api/asistentes")
    print("=" * 60)
    print(f"\nURL: {API_URL}")
    print(f"Token: {API_TOKEN[:20]}...")
    print(f"\nPayload enviado:")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    
    try:
        response = requests.post(API_URL, headers=headers, json=payload)
        print(f"\n✓ Status Code: {response.status_code}")
        
        data = response.json()
        print(f"\nRespuesta:")
        print(json.dumps(data, indent=2, ensure_ascii=False))
        
        if response.status_code == 201:
            print("\n✅ ÉXITO: Endpoint funcionando correctamente")
            if data.get('asistentes'):
                for asistente in data['asistentes']:
                    print(f"  - {asistente['nombre']}: {asistente['ticket_id']}")
        else:
            print(f"\n❌ ERROR: {data.get('error', 'Error desconocido')}")
            
    except Exception as e:
        print(f"\n❌ Error en la solicitud: {e}")
        print("   Verifica que el servidor está corriendo en http://localhost:5000")

if __name__ == '__main__':
    test_endpoint()
```

**Ejecutar:**
```bash
python test_api.py
```

---

## 5️⃣ Script de Prueba (Bash)

Guardar como `test_api.sh`:

```bash
#!/bin/bash

API_TOKEN="550e8400-e29b-41d4-a716-446655440000"
API_URL="http://localhost:5000/api/asistentes"

echo "========================================"
echo "Prueba de Endpoint API"
echo "========================================"
echo ""
echo "URL: $API_URL"
echo "Token: ${API_TOKEN:0:20}..."
echo ""

curl -X POST "$API_URL" \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "asistentes": [
      {
        "nombre": "Juan Pérez",
        "correo": "juan@test.com",
        "telefono": "1234567890"
      },
      {
        "nombre": "María García",
        "correo": "maria@test.com",
        "telefono": "0987654321"
      }
    ]
  }' \
  -w "\n\nStatus Code: %{http_code}\n"
```

**Ejecutar:**
```bash
chmod +x test_api.sh
./test_api.sh
```

---

## 6️⃣ Casos de Prueba

### Caso 1: Solicitud Exitosa
```json
POST /api/asistentes
Authorization: Bearer <TOKEN>
Content-Type: application/json

{
  "asistentes": [
    {
      "nombre": "Juan Pérez",
      "correo": "juan@email.com"
    }
  ]
}

RESPUESTA: 201 Created
```

### Caso 2: Sin Autenticación
```
POST /api/asistentes
(sin header Authorization)

RESPUESTA: 401 Unauthorized
{
  "error": "Autenticación requerida. Usar: Authorization: Bearer <token>"
}
```

### Caso 3: Token Inválido
```
Authorization: Bearer token_incorrecto

RESPUESTA: 403 Forbidden
{
  "error": "Token inválido o expirado"
}
```

### Caso 4: Campo Nombre Faltante
```json
{
  "asistentes": [
    {
      "correo": "sin_nombre@email.com"
    }
  ]
}

RESPUESTA: 201 (Parcial)
{
  "exitoso": true,
  "insertados": 0,
  "total_procesados": 1,
  "asistentes": [],
  "errores": ["Registro 0: nombre es requerido"]
}
```

---

## 7️⃣ Monitoreo y Logs

### Ver logs en tiempo real:

```bash
# Con tail
tail -f logs/app.log

# Con grep (solo errores de API)
tail -f logs/app.log | grep "API:"
```

### Formato esperado de logs:
```
[2026-04-30 10:15:23,456] INFO in routes: API: 2 asistentes registrados
[2026-04-30 10:16:45,123] ERROR in routes: Error en /api/asistentes: [descripción del error]
```

---

## 8️⃣ Control de Acceso (opcional)

Si necesitas limitar qué dominios pueden acceder al endpoint, añade CORS:

```python
# En extensions.py
from flask_cors import CORS

CORS(app, resources={
    r"/api/*": {
        "origins": ["https://tudominio.com", "https://www.tudominio.com"],
        "methods": ["POST"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})
```

Instalar:
```bash
pip install flask-cors
```

---

## 9️⃣ Documento de Entrega al Desarrollador

Crear archivo `API_CREDENTIALS.txt` (guardar de forma segura):

```
╔════════════════════════════════════════════════════════════╗
║       CREDENCIALES DE API - REGISTRO DE ASISTENTES        ║
║                     [CONFIDENCIAL]                        ║
╚════════════════════════════════════════════════════════════╝

ENDPOINT:
URL: https://tudominio.com/api/asistentes
Método: POST

AUTENTICACIÓN:
Token: 550e8400-e29b-41d4-a716-446655440000

HEADER REQUERIDO:
Authorization: Bearer 550e8400-e29b-41d4-a716-446655440000

DOCUMENTACIÓN:
- Documentación Completa: API_DOCUMENTATION.md
- Quick Start: API_QUICK_START.md
- Ejemplos de Código: EXAMPLES.md

CONTACTO TÉCNICO:
Email: [tu_email]
Teléfono: [tu_teléfono]

DATOS DE PRUEBA:
URL de Prueba: http://localhost:5000/api/asistentes (desarrollo)

Fecha de Generación: 30/04/2026
Válido desde: 30/04/2026
Vencimiento: Sin expiración (cambiar si es necesario)

⚠️ IMPORTANTE:
- No compartir este token públicamente
- No incluir en código fuente visible
- Usar variables de entorno
- Si se compromete, contactar inmediatamente al equipo técnico
```

---

## 🔟 Rotación de Tokens

Para cambiar el token (cada 6-12 meses recomendado):

1. Generar nuevo token:
   ```python
   import uuid
   nuevo_token = str(uuid.uuid4())
   print(nuevo_token)
   ```

2. Actualizar variables de entorno

3. Avisar al desarrollador de la landing page

4. Esperar confirmación de actualización

5. Guardar token anterior como "revocado"

---

## ✅ Validación Final

Antes de entregar al desarrollador, verificar:

- [x] Token generado y configurado
- [x] Endpoint probado y funcionando
- [x] Logs registrando correctamente
- [x] CORS configurado (si es necesario)
- [x] Documentación completa entregada
- [x] Desarrollador tiene acceso a documentación

---

**Generado**: 30 de abril de 2026
**Versión**: 1.0
**Responsable**: Administrador del Sistema
