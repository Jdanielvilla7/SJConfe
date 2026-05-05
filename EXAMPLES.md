# 💻 Ejemplos de Código - API Registro de Asistentes

## 📝 Tabla de Contenidos
1. [JavaScript (Vanilla)](#javascript-vanilla)
2. [React](#react)
3. [Vue.js](#vuejs)
4. [Angular](#angular)
5. [Python](#python)
6. [PHP](#php)
7. [jQuery](#jquery)

---

## JavaScript (Vanilla)

### Opción 1: Función Simple
```javascript
const API_TOKEN = 'tu_token_secreto';
const API_URL = 'https://tudominio.com/api/asistentes';

async function registrarAsistente(formData) {
  const response = await fetch(API_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${API_TOKEN}`
    },
    body: JSON.stringify({
      asistentes: [formData]
    })
  });

  if (!response.ok) {
    throw new Error(`Error: ${response.status}`);
  }

  return response.json();
}

// Uso:
document.getElementById('form').addEventListener('submit', async (e) => {
  e.preventDefault();
  
  const data = {
    nombre: document.getElementById('nombre').value,
    correo: document.getElementById('correo').value,
    telefono: document.getElementById('telefono').value
  };

  try {
    const resultado = await registrarAsistente(data);
    console.log('Ticket ID:', resultado.asistentes[0].ticket_id);
    alert('Asistente registrado');
  } catch (error) {
    console.error('Error:', error);
    alert('Error al registrar');
  }
});
```

### Opción 2: Clase Reutilizable
```javascript
class RegistroAsistentesAPI {
  constructor(token, url) {
    this.token = token;
    this.url = url;
  }

  async registrar(asistentes) {
    try {
      const response = await fetch(this.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.token}`
        },
        body: JSON.stringify({ asistentes })
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || `HTTP ${response.status}`);
      }

      return {
        exitoso: true,
        data: await response.json()
      };
    } catch (error) {
      return {
        exitoso: false,
        error: error.message
      };
    }
  }
}

// Uso:
const api = new RegistroAsistentesAPI(
  'tu_token_secreto',
  'https://tudominio.com/api/asistentes'
);

const resultado = await api.registrar([
  {
    nombre: 'Juan Pérez',
    correo: 'juan@email.com',
    telefono: '1234567890'
  }
]);

if (resultado.exitoso) {
  console.log('Ticket:', resultado.data.asistentes[0].ticket_id);
}
```

---

## React

### Hook Personalizado
```javascript
import { useState } from 'react';

const useRegistroAsistentes = () => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const registrar = async (asistentes) => {
    setLoading(true);
    setError(null);

    try {
      const response = await fetch('https://tudominio.com/api/asistentes', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${process.env.REACT_APP_API_TOKEN}`
        },
        body: JSON.stringify({ asistentes })
      });

      if (!response.ok) {
        const err = await response.json();
        throw new Error(err.error);
      }

      const data = await response.json();
      setLoading(false);
      return data;
    } catch (err) {
      setError(err.message);
      setLoading(false);
      return null;
    }
  };

  return { registrar, loading, error };
};

// Componente de Uso
function FormRegistroAsistente() {
  const { registrar, loading, error } = useRegistroAsistentes();
  const [nombre, setNombre] = useState('');
  const [correo, setCorreo] = useState('');
  const [ticketId, setTicketId] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    const resultado = await registrar([{ nombre, correo }]);
    if (resultado) {
      setTicketId(resultado.asistentes[0].ticket_id);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="text"
        placeholder="Nombre"
        value={nombre}
        onChange={(e) => setNombre(e.target.value)}
        required
      />
      <input
        type="email"
        placeholder="Correo"
        value={correo}
        onChange={(e) => setCorreo(e.target.value)}
        required
      />
      <button type="submit" disabled={loading}>
        {loading ? 'Registrando...' : 'Registrar'}
      </button>
      {error && <p style={{ color: 'red' }}>{error}</p>}
      {ticketId && <p style={{ color: 'green' }}>ID: {ticketId}</p>}
    </form>
  );
}

export default FormRegistroAsistente;
```

### Con el archivo .env:
```
REACT_APP_API_TOKEN=tu_token_secreto
REACT_APP_API_URL=https://tudominio.com/api/asistentes
```

---

## Vue.js

### Composable para Vue 3
```javascript
// composables/useRegistroAsistentes.js
import { ref } from 'vue';

export function useRegistroAsistentes() {
  const loading = ref(false);
  const error = ref(null);

  const registrar = async (asistentes) => {
    loading.value = true;
    error.value = null;

    try {
      const response = await fetch(
        'https://tudominio.com/api/asistentes',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${import.meta.env.VITE_API_TOKEN}`
          },
          body: JSON.stringify({ asistentes })
        }
      );

      if (!response.ok) {
        const err = await response.json();
        throw new Error(err.error);
      }

      return await response.json();
    } catch (err) {
      error.value = err.message;
      return null;
    } finally {
      loading.value = false;
    }
  };

  return { registrar, loading, error };
}
```

### Componente Vue
```vue
<template>
  <form @submit.prevent="handleSubmit">
    <input
      v-model="nombre"
      type="text"
      placeholder="Nombre"
      required
    />
    <input
      v-model="correo"
      type="email"
      placeholder="Correo"
      required
    />
    <button type="submit" :disabled="loading">
      {{ loading ? 'Registrando...' : 'Registrar' }}
    </button>
    <p v-if="error" style="color: red;">{{ error }}</p>
    <p v-if="ticketId" style="color: green;">ID: {{ ticketId }}</p>
  </form>
</template>

<script setup>
import { ref } from 'vue';
import { useRegistroAsistentes } from '@/composables/useRegistroAsistentes';

const nombre = ref('');
const correo = ref('');
const ticketId = ref(null);
const { registrar, loading, error } = useRegistroAsistentes();

const handleSubmit = async () => {
  const resultado = await registrar([{ nombre: nombre.value, correo: correo.value }]);
  if (resultado) {
    ticketId.value = resultado.asistentes[0].ticket_id;
  }
};
</script>
```

---

## Angular

### Servicio
```typescript
// services/registro-asistentes.service.ts
import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface Asistente {
  nombre: string;
  correo?: string;
  telefono?: string;
  [key: string]: any;
}

export interface RespuestaAPI {
  exitoso: boolean;
  insertados: number;
  total_procesados: number;
  asistentes: Array<any>;
  errores: string[] | null;
}

@Injectable({
  providedIn: 'root'
})
export class RegistroAsistentesService {
  private apiUrl = 'https://tudominio.com/api/asistentes';
  private token = 'tu_token_secreto';

  constructor(private http: HttpClient) {}

  registrarAsistentes(asistentes: Asistente[]): Observable<RespuestaAPI> {
    const headers = new HttpHeaders({
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${this.token}`
    });

    return this.http.post<RespuestaAPI>(
      this.apiUrl,
      { asistentes },
      { headers }
    );
  }
}
```

### Componente
```typescript
// components/formulario-registro/formulario-registro.component.ts
import { Component } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { RegistroAsistentesService } from '../../services/registro-asistentes.service';

@Component({
  selector: 'app-formulario-registro',
  templateUrl: './formulario-registro.component.html',
  styleUrls: ['./formulario-registro.component.css']
})
export class FormularioRegistroComponent {
  form: FormGroup;
  loading = false;
  ticketId = '';
  error = '';

  constructor(
    private fb: FormBuilder,
    private registroService: RegistroAsistentesService
  ) {
    this.form = this.fb.group({
      nombre: ['', Validators.required],
      correo: ['', [Validators.required, Validators.email]],
      telefono: ['']
    });
  }

  onSubmit() {
    if (this.form.invalid) return;

    this.loading = true;
    this.error = '';

    this.registroService.registrarAsistentes([this.form.value])
      .subscribe({
        next: (respuesta) => {
          this.ticketId = respuesta.asistentes[0].ticket_id;
          this.loading = false;
        },
        error: (err) => {
          this.error = err.error?.error || 'Error al registrar';
          this.loading = false;
        }
      });
  }
}
```

### Template
```html
<!-- formulario-registro.component.html -->
<form [formGroup]="form" (ngSubmit)="onSubmit()">
  <input
    formControlName="nombre"
    type="text"
    placeholder="Nombre"
    required
  />
  <input
    formControlName="correo"
    type="email"
    placeholder="Correo"
    required
  />
  <input
    formControlName="telefono"
    type="text"
    placeholder="Teléfono"
  />
  <button type="submit" [disabled]="loading">
    {{ loading ? 'Registrando...' : 'Registrar' }}
  </button>
  <p *ngIf="error" style="color: red;">{{ error }}</p>
  <p *ngIf="ticketId" style="color: green;">ID: {{ ticketId }}</p>
</form>
```

---

## Python

### Con Requests
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
    
    payload = {'asistentes': asistentes}
    
    try:
        response = requests.post(API_URL, headers=headers, json=payload)
        response.raise_for_status()
        
        data = response.json()
        return {'exitoso': True, 'data': data}
    except requests.exceptions.RequestException as e:
        return {'exitoso': False, 'error': str(e)}

# Uso
resultado = registrar_asistentes([
    {
        'nombre': 'Juan Pérez',
        'correo': 'juan@email.com',
        'telefono': '1234567890'
    }
])

if resultado['exitoso']:
    ticket = resultado['data']['asistentes'][0]['ticket_id']
    print(f'Ticket generado: {ticket}')
else:
    print(f'Error: {resultado["error"]}')
```

### Con Async/Await
```python
import aiohttp
import asyncio

API_TOKEN = 'tu_token_secreto'
API_URL = 'https://tudominio.com/api/asistentes'

async def registrar_asistentes_async(asistentes):
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {API_TOKEN}'
    }
    
    payload = {'asistentes': asistentes}
    
    async with aiohttp.ClientSession() as session:
        async with session.post(API_URL, headers=headers, json=payload) as response:
            if response.status == 201:
                return await response.json()
            else:
                raise Exception(f'Error {response.status}: {await response.text()}')

# Uso
async def main():
    resultado = await registrar_asistentes_async([
        {'nombre': 'Juan', 'correo': 'juan@email.com'}
    ])
    print(resultado)

asyncio.run(main())
```

---

## PHP

### Función Simple
```php
<?php

function registrarAsistentes($asistentes, $token) {
    $url = 'https://tudominio.com/api/asistentes';
    
    $payload = json_encode(['asistentes' => $asistentes]);
    
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json',
        'Authorization: Bearer ' . $token
    ]);
    
    $response = curl_exec($ch);
    $statusCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($statusCode === 201) {
        return json_decode($response, true);
    } else {
        throw new Exception('Error: ' . $response);
    }
}

// Uso
try {
    $resultado = registrarAsistentes(
        [
            [
                'nombre' => 'Juan Pérez',
                'correo' => 'juan@email.com',
                'telefono' => '1234567890'
            ]
        ],
        'tu_token_secreto'
    );
    
    echo 'Ticket: ' . $resultado['asistentes'][0]['ticket_id'];
} catch (Exception $e) {
    echo 'Error: ' . $e->getMessage();
}
?>
```

### Con Guzzle
```php
<?php

require 'vendor/autoload.php';

use GuzzleHttp\Client;

$client = new Client();

try {
    $response = $client->request('POST', 'https://tudominio.com/api/asistentes', [
        'headers' => [
            'Content-Type' => 'application/json',
            'Authorization' => 'Bearer tu_token_secreto'
        ],
        'json' => [
            'asistentes' => [
                [
                    'nombre' => 'Juan Pérez',
                    'correo' => 'juan@email.com',
                    'telefono' => '1234567890'
                ]
            ]
        ]
    ]);
    
    $data = json_decode($response->getBody(), true);
    echo 'Ticket: ' . $data['asistentes'][0]['ticket_id'];
} catch (Exception $e) {
    echo 'Error: ' . $e->getMessage();
}
?>
```

---

## jQuery

```html
<!DOCTYPE html>
<html>
<head>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
</head>
<body>
    <form id="formRegistro">
        <input type="text" id="nombre" placeholder="Nombre" required />
        <input type="email" id="correo" placeholder="Correo" required />
        <input type="tel" id="telefono" placeholder="Teléfono" />
        <button type="submit">Registrar</button>
    </form>
    <div id="resultado"></div>

    <script>
        $('#formRegistro').on('submit', function(e) {
            e.preventDefault();
            
            var data = {
                asistentes: [{
                    nombre: $('#nombre').val(),
                    correo: $('#correo').val(),
                    telefono: $('#telefono').val()
                }]
            };
            
            $.ajax({
                url: 'https://tudominio.com/api/asistentes',
                type: 'POST',
                contentType: 'application/json',
                headers: {
                    'Authorization': 'Bearer tu_token_secreto'
                },
                data: JSON.stringify(data),
                success: function(response) {
                    var ticket = response.asistentes[0].ticket_id;
                    $('#resultado').html(
                        '<p style="color: green;">Ticket generado: ' + ticket + '</p>'
                    );
                },
                error: function(xhr) {
                    var error = xhr.responseJSON?.error || 'Error al registrar';
                    $('#resultado').html(
                        '<p style="color: red;">' + error + '</p>'
                    );
                }
            });
        });
    </script>
</body>
</html>
```

---

**Elige el ejemplo que mejor se ajuste a tu stack tecnológico y adaptalo según tus necesidades.**
