# 🚀 Quick Start - API Registro de Asistentes

## URL del Endpoint
```
POST https://tudominio.com/api/asistentes
```

## Token de Autenticación
```
Authorization: Bearer <TOKEN>
```

## Solicitud Mínima (JSON)
```json
{
  "asistentes": [
    {
      "nombre": "Juan Pérez",
      "correo": "juan@email.com"
    }
  ]
}
```

## Respuesta (201 Created)
```json
{
  "exitoso": true,
  "insertados": 1,
  "total_procesados": 1,
  "asistentes": [
    {
      "nombre": "Juan Pérez",
      "ticket_id": "550e8400-e29b-41d4-a716-446655440000",
      "correo": "juan@email.com"
    }
  ],
  "errores": null
}
```

## Consumir con Fetch
```javascript
const token = 'tu_token_aqui';

async function registrar(asistentes) {
  const res = await fetch('https://tudominio.com/api/asistentes', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({ asistentes })
  });
  
  return res.json();
}

// Usar:
registrar([
  { nombre: 'Juan', correo: 'juan@email.com' }
]).then(data => {
  console.log('Ticket:', data.asistentes[0].ticket_id);
});
```

## Errores Comunes

| Error | Solución |
|-------|----------|
| 401 Unauthorized | Falta header `Authorization: Bearer <TOKEN>` |
| 403 Forbidden | Token inválido - obtén uno nuevo |
| 400 Bad Request | JSON mal formado o falta campo `asistentes` |
| Sin `nombre` | Es requerido en cada asistente |

## Todos los Campos Disponibles
```json
{
  "nombre": "string (requerido)",
  "correo": "string",
  "telefono": "string",
  "edad": "string o número",
  "cabana": "string",
  "lider": "string",
  "registro": "string",
  "alergias": "string",
  "alimentos": "string",
  "medicamentos": "string",
  "nada": "string"
}
```

---
Para documentación completa, ver: **API_DOCUMENTATION.md**
