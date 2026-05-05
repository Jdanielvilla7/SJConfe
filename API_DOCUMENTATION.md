# 📋 Documentación API - Registro de Asistentes
## SJConfe - Sistema de Gestión de Conferencia

---

## 📌 Descripción General

Este documento describe el endpoint de API para registrar asistentes a la conferencia. El endpoint genera automáticamente un `ticket_id` único (UUID) para cada asistente registrado, que se utiliza para generar el código QR y realizar el check-in en el evento.

---

## 🔐 Autenticación

Todo request al endpoint debe incluir un **Bearer Token** en el header `Authorization`.

### Header requerido:
```
Authorization: Bearer <TOKEN>
```

### Obtener el Token:
Contacta al administrador del sistema para obtener tu token de API.

⚠️ **IMPORTANTE**: Mantén el token seguro. No lo compartas públicamente o en solicitudes de JavaScript del lado del cliente que sean visibles.

---

## 🌐 Endpoint

### POST `/api/asistentes`

**Base URL:** `https://tudominio.com` (o `http://localhost:5000` en desarrollo)

**URL Completa:** `POST https://tudominio.com/api/asistentes`

---

## 📤 Solicitud (Request)

### Headers requeridos:
```
Content-Type: application/json
Authorization: Bearer <TOKEN>
```

### Body (JSON):

```json
{
  "asistentes": [
    {
      "nombre": "string (requerido)",
      "correo": "string",
      "cabana": "string",
      "lider": "string",
      "telefono": "string",
      "edad": "string o número",
      "registro": "string",
      "alergias": "string",
      "alimentos": "string",
      "medicamentos": "string",
      "nada": "string"
    }
  ]
}
```

### Campos:

| Campo | Tipo | Requerido | Descripción |
|-------|------|-----------|-------------|
| `nombre` | string | ✅ Sí | Nombre completo del asistente |
| `correo` | string | ❌ No | Email del asistente (usar para enviar QR) |
| `cabana` | string | ❌ No | Cabaña asignada |
| `lider` | string | ❌ No | Líder responsable |
| `telefono` | string | ❌ No | Número de teléfono |
| `edad` | string/número | ❌ No | Edad del asistente |
| `registro` | string | ❌ No | Tipo de registro ("Online", "Presencial", etc.) |
| `alergias` | string | ❌ No | Alergias alimentarias |
| `alimentos` | string | ❌ No | Restricciones de alimentos |
| `medicamentos` | string | ❌ No | Medicamentos que toma |
| `nada` | string | ❌ No | Campo adicional |

---

## 📥 Respuesta (Response)

### Éxito (201 Created):

```json
{
  "exitoso": true,
  "insertados": 2,
  "total_procesados": 2,
  "asistentes": [
    {
      "nombre": "Juan Pérez",
      "ticket_id": "550e8400-e29b-41d4-a716-446655440000",
      "correo": "juan@email.com"
    },
    {
      "nombre": "María García",
      "ticket_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
      "correo": "maria@email.com"
    }
  ],
  "errores": null
}
```

### Con errores de validación (Algunos registrados, algunos fallidos):

```json
{
  "exitoso": true,
  "insertados": 1,
  "total_procesados": 2,
  "asistentes": [
    {
      "nombre": "Juan Pérez",
      "ticket_id": "550e8400-e29b-41d4-a716-446655440000",
      "correo": "juan@email.com"
    }
  ],
  "errores": [
    "Registro 1: nombre es requerido"
  ]
}
```

### Errores de solicitud:

#### 400 Bad Request - JSON vacío:
```json
{
  "error": "JSON vacío"
}
```

#### 400 Bad Request - Campo asistentes faltante:
```json
{
  "error": "El campo \"asistentes\" es requerido y debe ser una lista"
}
```

#### 401 Unauthorized - Sin token:
```json
{
  "error": "Autenticación requerida. Usar: Authorization: Bearer <token>"
}
```

#### 403 Forbidden - Token inválido:
```json
{
  "error": "Token inválido o expirado"
}
```

#### 500 Internal Server Error:
```json
{
  "error": "Error al procesar la solicitud: [detalles del error]"
}
```

---

## 💡 Ejemplos de Uso

### 1️⃣ cURL (Terminal)

**Un asistente:**
```bash
curl -X POST https://tudominio.com/api/asistentes \
  -H "Authorization: Bearer tu_token_secreto" \
  -H "Content-Type: application/json" \
  -d '{
    "asistentes": [
      {
        "nombre": "Juan Pérez",
        "correo": "juan@email.com",
        "cabana": "Cabaña 1",
        "lider": "Carlos López",
        "telefono": "1234567890",
        "edad": "25",
        "alergias": "Ninguna"
      }
    ]
  }'
```

**Múltiples asistentes:**
```bash
curl -X POST https://tudominio.com/api/asistentes \
  -H "Authorization: Bearer tu_token_secreto" \
  -H "Content-Type: application/json" \
  -d '{
    "asistentes": [
      {
        "nombre": "Juan Pérez",
        "correo": "juan@email.com",
        "cabana": "Cabaña 1",
        "lider": "Carlos López",
        "telefono": "1234567890",
        "edad": "25"
      },
      {
        "nombre": "María García",
        "correo": "maria@email.com",
        "cabana": "Cabaña 2",
        "lider": "Ana Rodríguez",
        "telefono": "9876543210",
        "edad": "22"
      }
    ]
  }'
```

---

### 2️⃣ JavaScript (Fetch API)

```javascript
const API_TOKEN = 'tu_token_secreto';
const API_URL = 'https://tudominio.com/api/asistentes';

async function registrarAsistentes(asistentes) {
  try {
    const response = await fetch(API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${API_TOKEN}`
      },
      body: JSON.stringify({
        asistentes: asistentes
      })
    });

    if (!response.ok) {
      const error = await response.json();
      console.error('Error:', error);
      return null;
    }

    const data = await response.json();
    console.log('Asistentes registrados:', data);
    
    // Aquí puedes usar los ticket_ids para generar QRs y enviar correos
    data.asistentes.forEach(asistente => {
      console.log(`${asistente.nombre}: ${asistente.ticket_id}`);
    });

    return data;
  } catch (error) {
    console.error('Error en la solicitud:', error);
    return null;
  }
}

// Uso:
const nuevosAsistentes = [
  {
    nombre: 'Juan Pérez',
    correo: 'juan@email.com',
    cabana: 'Cabaña 1',
    lider: 'Carlos López',
    telefono: '1234567890',
    edad: '25'
  },
  {
    nombre: 'María García',
    correo: 'maria@email.com',
    cabana: 'Cabaña 2',
    lider: 'Ana Rodríguez',
    telefono: '9876543210',
    edad: '22'
  }
];

registrarAsistentes(nuevosAsistentes);
```

---

### 3️⃣ Python (Requests)

```python
import requests
import json

API_TOKEN = 'tu_token_secreto'
API_URL = 'https://tudominio.com/api/asistentes'

def registrar_asistentes(asistentes):
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {API_TOKEN}'
    }
    
    payload = {
        'asistentes': asistentes
    }
    
    try:
        response = requests.post(API_URL, headers=headers, json=payload)
        response.raise_for_status()
        
        data = response.json()
        print('Asistentes registrados:', json.dumps(data, indent=2))
        
        # Usar los ticket_ids para generar QRs y enviar correos
        for asistente in data.get('asistentes', []):
            print(f"{asistente['nombre']}: {asistente['ticket_id']}")
        
        return data
    except requests.exceptions.RequestException as e:
        print(f'Error en la solicitud: {e}')
        return None

# Uso:
nuevos_asistentes = [
    {
        'nombre': 'Juan Pérez',
        'correo': 'juan@email.com',
        'cabana': 'Cabaña 1',
        'lider': 'Carlos López',
        'telefono': '1234567890',
        'edad': '25'
    },
    {
        'nombre': 'María García',
        'correo': 'maria@email.com',
        'cabana': 'Cabaña 2',
        'lider': 'Ana Rodríguez',
        'telefono': '9876543210',
        'edad': '22'
    }
]

registrar_asistentes(nuevos_asistentes)
```

---

### 4️⃣ PHP

```php
<?php

$API_TOKEN = 'tu_token_secreto';
$API_URL = 'https://tudominio.com/api/asistentes';

function registrar_asistentes($asistentes) {
    global $API_TOKEN, $API_URL;
    
    $payload = json_encode([
        'asistentes' => $asistentes
    ]);
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $API_URL);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json',
        'Authorization: Bearer ' . $API_TOKEN
    ]);
    
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($http_code === 201) {
        $data = json_decode($response, true);
        echo 'Asistentes registrados: ' . json_encode($data, JSON_PRETTY_PRINT);
        
        // Usar los ticket_ids
        foreach ($data['asistentes'] as $asistente) {
            echo $asistente['nombre'] . ': ' . $asistente['ticket_id'] . "\n";
        }
        
        return $data;
    } else {
        echo 'Error: ' . $response;
        return null;
    }
}

// Uso:
$nuevos_asistentes = [
    [
        'nombre' => 'Juan Pérez',
        'correo' => 'juan@email.com',
        'cabana' => 'Cabaña 1',
        'lider' => 'Carlos López',
        'telefono' => '1234567890',
        'edad' => '25'
    ],
    [
        'nombre' => 'María García',
        'correo' => 'maria@email.com',
        'cabana' => 'Cabaña 2',
        'lider' => 'Ana Rodríguez',
        'telefono' => '9876543210',
        'edad' => '22'
    ]
];

registrar_asistentes($nuevos_asistentes);
?>
```

---

## 🎯 Flujo de Integración Recomendado

```
1. Usuario compra entrada en landing page
   ↓
2. Formulario de datos del asistente
   ↓
3. Submit → POST /api/asistentes
   ↓
4. Recibir response con ticket_id
   ↓
5. Generar QR con el ticket_id
   ↓
6. Enviar correo con el QR al asistente
   ↓
7. Asistente usa el QR en el evento
```

---

## ⚙️ Consideraciones Técnicas

### Límites de Solicitud:
- **Máximo asistentes por solicitud**: Sin límite definido (recomendado ≤ 100)
- **Timeout**: 30 segundos
- **Rate Limiting**: No implementado (contacta al admin si hay cambios)

### Validaciones:
- ✅ `nombre` es **obligatorio**
- ✅ `ticket_id` se genera automáticamente (UUID v4)
- ✅ No se permiten nombres duplicados en una solicitud
- ✅ Los correos se aceptan sin validación de formato (validar en cliente)

### Datos Guardados:
```
- ticket_id (UUID - generado)
- Todos los campos proporcionados
- fecha_registro_api (timestamp en zona horaria de Guatemala)
- checked_in: false (estado inicial)
```

---

## 🚨 Manejo de Errores

### Estrategia recomendada:

```javascript
async function registrarConManejoDeErrores(asistentes) {
  try {
    const response = await fetch(API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${API_TOKEN}`
      },
      body: JSON.stringify({ asistentes })
    });

    switch (response.status) {
      case 201:
        const data = await response.json();
        // ✅ Éxito parcial o total
        console.log(`${data.insertados} registrados, ${data.errores?.length || 0} errores`);
        return data;
      
      case 401:
        console.error('❌ Token no proporcionado o falta header Authorization');
        return null;
      
      case 403:
        console.error('❌ Token inválido o expirado');
        return null;
      
      case 400:
        const error = await response.json();
        console.error('❌ Solicitud inválida:', error.error);
        return null;
      
      case 500:
        console.error('❌ Error en el servidor. Intenta más tarde.');
        return null;
      
      default:
        console.error(`❌ Error desconocido: ${response.status}`);
        return null;
    }
  } catch (error) {
    console.error('❌ Error de red:', error);
    return null;
  }
}
```

---

## ✔️ Checklist para Implementación

- [ ] Obtener el token de API del administrador
- [ ] Configurar el token en la landing page (variable de entorno o config segura)
- [ ] Implementar formulario de registro de asistente
- [ ] Realizar solicitud POST al endpoint con validación
- [ ] Manejar respuestas exitosas y errores
- [ ] Implementar generación de QR con el `ticket_id`
- [ ] Implementar envío de correo con QR
- [ ] Probar en desarrollo antes de producción
- [ ] Contactar al administrador para configurar rate limiting si es necesario

---

## 📞 Soporte y Contacto

| Asunto | Contacto |
|--------|----------|
| Problemas técnicos | [Email/Slack del admin] |
| Solicitud de token | [Email/Slack del admin] |
| Cambios en el API | Notificación anticipada |

---

## 📝 Historial de Cambios

| Versión | Fecha | Cambios |
|---------|-------|---------|
| 1.0 | 30/04/2026 | Versión inicial - Endpoint POST /api/asistentes |

---

**Última actualización**: 30 de abril de 2026
**Versión del API**: 1.0
**Estado**: ✅ Activo

