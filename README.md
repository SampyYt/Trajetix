# Trajetix - Backend local con base de datos

## Ejecutar

Desde esta carpeta:

```powershell
python server.py
```

Abrir:

```text
http://127.0.0.1:8080/index.html
```

## Base de datos

El servidor crea automaticamente:

```text
outputs/data/trajetix.db
```

Tablas principales:

- `companies`: companias registradas.
- `users`: usuarios, roles y credenciales.
- `orders`: ordenes creadas desde Trajetix.
- `courier_guides`: guias creadas para Laar Courier y Servientrega.
- `audit_log`: acciones realizadas por cada usuario.
- `email_outbox`: correos de registro enviados o pendientes.

## Correo de registro

Si configuras SMTP, Trajetix intenta enviar el correo real:

```powershell
$env:TRAJETIX_SMTP_HOST="smtp.tudominio.com"
$env:TRAJETIX_SMTP_PORT="587"
$env:TRAJETIX_SMTP_USER="no-reply@tudominio.com"
$env:TRAJETIX_SMTP_PASSWORD="tu_password"
$env:TRAJETIX_SMTP_FROM="Trajetix <no-reply@tudominio.com>"
python server.py
```

Si no configuras SMTP, el correo queda guardado en `email_outbox` con estado `pendiente`.

## Guias courier

Desde el apartado de ordenes puedes crear guias para:

- Laar Courier
- Servientrega

El servidor genera una guia demo y la guarda en `courier_guides`.
