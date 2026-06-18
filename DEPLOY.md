# Publicar Trajetix en internet

## Opcion recomendada: Render

1. Crea una cuenta en https://render.com.
2. Sube la carpeta `outputs` a un repositorio de GitHub.
3. En Render elige `New +` > `Web Service`.
4. Conecta el repositorio.
5. Configura:
   - Root directory: `outputs`
   - Runtime: `Python`
   - Build command: `pip install -r requirements.txt`
   - Start command: `python server.py`
6. Publica el servicio.

Render entregara una URL parecida a:

```text
https://trajetix.onrender.com
```

## Variables utiles

Render define `PORT` automaticamente. Trajetix ya lo usa.

Opcional:

```text
HOST=0.0.0.0
```

## Importante sobre la base de datos

Trajetix usa SQLite en `outputs/data/trajetix.db`. En hosting gratuito, algunos servicios pueden borrar archivos locales cuando redeployan. Para uso real con muchos usuarios conviene migrar luego a PostgreSQL.

Para una primera version publica, Render funciona bien para probar registros, login, guias y tracking.
