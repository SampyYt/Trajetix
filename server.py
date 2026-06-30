from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
from pathlib import Path
import base64
import hashlib
import hmac
import json
import os
import secrets
import smtplib
import sqlite3
import time


ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "data" / "trajetix.db"
SESSIONS = {}


def connect_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000)
    return salt, base64.b64encode(digest).decode()


def verify_password(password, salt, stored_hash):
    _, candidate = hash_password(password, salt)
    return hmac.compare_digest(candidate, stored_hash)


def init_db():
    with connect_db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS companies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                legal_name TEXT NOT NULL,
                trade_name TEXT NOT NULL,
                tax_id TEXT,
                id_type TEXT DEFAULT 'RUC',
                legal_form TEXT,
                vat_regime TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                company_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                phone TEXT,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'Administrador',
                status TEXT NOT NULL DEFAULT 'Activo',
                created_at TEXT NOT NULL,
                FOREIGN KEY(company_id) REFERENCES companies(id)
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                company_id INTEGER,
                action TEXT NOT NULL,
                entity TEXT,
                payload TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(company_id) REFERENCES companies(id)
            );

            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                company_id INTEGER NOT NULL,
                guide TEXT NOT NULL,
                customer TEXT NOT NULL,
                customer_id TEXT,
                phone TEXT,
                city TEXT NOT NULL,
                sector TEXT,
                address TEXT,
                reference TEXT,
                origin_mode TEXT,
                sender_warehouse TEXT,
                sender_name TEXT,
                sender_phone TEXT,
                sender_id TEXT,
                sender_city TEXT,
                sender_address TEXT,
                courier TEXT NOT NULL,
                status TEXT NOT NULL,
                amount REAL NOT NULL,
                payment TEXT,
                sku TEXT,
                external_ref TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(company_id) REFERENCES companies(id)
            );

            CREATE TABLE IF NOT EXISTS courier_guides (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                company_id INTEGER NOT NULL,
                order_guide TEXT NOT NULL,
                courier TEXT NOT NULL,
                courier_guide TEXT NOT NULL UNIQUE,
                label_url TEXT,
                status TEXT NOT NULL,
                payload TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(company_id) REFERENCES companies(id)
            );

            CREATE TABLE IF NOT EXISTS warehouses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                company_id INTEGER NOT NULL,
                external_id TEXT,
                name TEXT NOT NULL,
                city TEXT NOT NULL,
                address TEXT NOT NULL,
                manager TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(company_id) REFERENCES companies(id)
            );

            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                company_id INTEGER NOT NULL,
                sku TEXT NOT NULL,
                product TEXT NOT NULL,
                warehouse TEXT,
                location TEXT,
                available REAL NOT NULL DEFAULT 0,
                reserved REAL NOT NULL DEFAULT 0,
                min_stock REAL NOT NULL DEFAULT 0,
                price REAL NOT NULL DEFAULT 0,
                weight_kg REAL NOT NULL DEFAULT 0,
                length_cm REAL NOT NULL DEFAULT 0,
                width_cm REAL NOT NULL DEFAULT 0,
                height_cm REAL NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(company_id, sku),
                FOREIGN KEY(company_id) REFERENCES companies(id)
            );

            CREATE TABLE IF NOT EXISTS sales (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                company_id INTEGER NOT NULL,
                code TEXT NOT NULL,
                customer TEXT NOT NULL,
                payment TEXT,
                delivery TEXT,
                total REAL NOT NULL,
                lines TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(company_id) REFERENCES companies(id)
            );

            CREATE TABLE IF NOT EXISTS bank_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                company_id INTEGER NOT NULL,
                external_id TEXT,
                bank TEXT NOT NULL,
                account_type TEXT NOT NULL,
                account_number TEXT NOT NULL,
                masked TEXT NOT NULL,
                holder_name TEXT NOT NULL,
                holder_id TEXT NOT NULL,
                status TEXT NOT NULL,
                validation_message TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(company_id) REFERENCES companies(id)
            );

            CREATE TABLE IF NOT EXISTS withdrawals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                company_id INTEGER NOT NULL,
                external_id TEXT,
                code TEXT NOT NULL,
                bank_account_id TEXT NOT NULL,
                bank_label TEXT NOT NULL,
                amount REAL NOT NULL,
                reference TEXT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(company_id) REFERENCES companies(id)
            );

            CREATE TABLE IF NOT EXISTS email_outbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                to_email TEXT NOT NULL,
                subject TEXT NOT NULL,
                body TEXT NOT NULL,
                status TEXT NOT NULL,
                error TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS integration_api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                company_id INTEGER NOT NULL,
                integration_id TEXT,
                name TEXT NOT NULL,
                provider TEXT,
                prefix TEXT NOT NULL,
                key_hash TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'Activa',
                created_at TEXT NOT NULL,
                last_used_at TEXT,
                FOREIGN KEY(company_id) REFERENCES companies(id)
            );

            CREATE TABLE IF NOT EXISTS integration_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                company_id INTEGER NOT NULL,
                integration_id TEXT,
                event TEXT NOT NULL,
                detail TEXT,
                level TEXT NOT NULL DEFAULT 'info',
                created_at TEXT NOT NULL,
                FOREIGN KEY(company_id) REFERENCES companies(id)
            );
            """
        )

        existing_order_columns = {row["name"] for row in conn.execute("PRAGMA table_info(orders)").fetchall()}
        order_columns = {
            "customer_id": "TEXT",
            "phone": "TEXT",
            "sector": "TEXT",
            "address": "TEXT",
            "reference": "TEXT",
            "origin_mode": "TEXT",
            "sender_warehouse": "TEXT",
            "sender_name": "TEXT",
            "sender_phone": "TEXT",
            "sender_id": "TEXT",
            "sender_city": "TEXT",
            "sender_address": "TEXT",
            "external_ref": "TEXT",
        }
        for column, column_type in order_columns.items():
            if column not in existing_order_columns:
                conn.execute(f"ALTER TABLE orders ADD COLUMN {column} {column_type}")

        existing_product_columns = {row["name"] for row in conn.execute("PRAGMA table_info(products)").fetchall()}
        product_columns = {
            "weight_kg": "REAL NOT NULL DEFAULT 0",
            "length_cm": "REAL NOT NULL DEFAULT 0",
            "width_cm": "REAL NOT NULL DEFAULT 0",
            "height_cm": "REAL NOT NULL DEFAULT 0",
        }
        for column, column_type in product_columns.items():
            if column not in existing_product_columns:
                conn.execute(f"ALTER TABLE products ADD COLUMN {column} {column_type}")

        if not conn.execute("SELECT 1 FROM companies LIMIT 1").fetchone():
            conn.execute(
                """
                INSERT INTO companies
                (legal_name, trade_name, tax_id, id_type, legal_form, vat_regime, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "Dropshipping Ecuador S.A.",
                    "Trajetix Fulfillment",
                    "1790012345001",
                    "RUC",
                    "Sociedad Anonima",
                    "Regimen General IVA 15%",
                    now(),
                ),
            )
            company_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            salt, pwd_hash = hash_password("trajetix123")
            conn.execute(
                """
                INSERT INTO users
                (company_id, name, email, phone, password_salt, password_hash, role, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    company_id,
                    "Administrador Trajetix",
                    "admin@trajetix.ec",
                    "0990000000",
                    salt,
                    pwd_hash,
                    "Administrador",
                    "Activo",
                    now(),
                ),
            )
            conn.commit()


def json_response(handler, status, payload):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
    handler.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def read_json(handler):
    length = int(handler.headers.get("Content-Length", "0"))
    if not length:
        return {}
    return json.loads(handler.rfile.read(length).decode("utf-8"))


def current_session(handler):
    auth = handler.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return SESSIONS.get(auth[7:])
    return None


def audit(conn, session, action, entity=None, payload=None):
    conn.execute(
        """
        INSERT INTO audit_log (user_id, company_id, action, entity, payload, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            session.get("user_id") if session else None,
            session.get("company_id") if session else None,
            action,
            entity,
            json.dumps(payload or {}, ensure_ascii=False),
            now(),
        ),
    )


def send_registration_email(conn, user_id, email, name):
    subject = "Registro exitoso en Trajetix Sistema para Ecommerce"
    body = (
        f"Hola {name},\n\n"
        "Tu registro en Trajetix Sistema para Ecommerce fue creado correctamente.\n"
        "Ya puedes iniciar sesion, conectar tu tienda, activar couriers y gestionar envios.\n\n"
        "Trajetix - Envios sin limites"
    )
    status = "pendiente"
    error = None

    smtp_host = os.getenv("TRAJETIX_SMTP_HOST")
    smtp_user = os.getenv("TRAJETIX_SMTP_USER")
    smtp_password = os.getenv("TRAJETIX_SMTP_PASSWORD")
    smtp_from = os.getenv("TRAJETIX_SMTP_FROM", smtp_user or "no-reply@trajetix.ec")
    smtp_port = int(os.getenv("TRAJETIX_SMTP_PORT", "587"))

    if smtp_host and smtp_user and smtp_password:
        try:
            message = (
                f"From: {smtp_from}\r\n"
                f"To: {email}\r\n"
                f"Subject: {subject}\r\n"
                "Content-Type: text/plain; charset=utf-8\r\n\r\n"
                f"{body}"
            )
            with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as smtp:
                smtp.starttls()
                smtp.login(smtp_user, smtp_password)
                smtp.sendmail(smtp_from, [email], message.encode("utf-8"))
            status = "enviado"
        except Exception as exc:
            status = "error"
            error = str(exc)

    conn.execute(
        """
        INSERT INTO email_outbox (user_id, to_email, subject, body, status, error, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (user_id, email, subject, body, status, error, now()),
    )
    return status


def public_user(row):
    return {
        "id": row["id"],
        "profile_id": f"TJX-U-{int(row['id']):06d}",
        "company_id": row["company_id"],
        "name": row["name"],
        "email": row["email"],
        "phone": row["phone"],
        "role": row["role"],
        "status": row["status"],
    }


def make_courier_guide(courier, order_guide):
    normalized = courier.lower().replace(" ", "")
    if "laar" in normalized:
        prefix = "LAAR"
    elif "servientrega" in normalized:
        prefix = "SERV"
    else:
        raise ValueError("Solo se pueden crear guias de Laar Courier o Servientrega")
    return f"{prefix}-{int(time.time())}-{secrets.randbelow(9000) + 1000}"


def hash_api_key(secret):
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def authenticate_api_key(handler):
    auth = handler.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        api_key = handler.headers.get("X-Trajetix-Key", "")
        if not api_key:
            api_key = parse_qs(urlparse(handler.path).query).get("api_key", [""])[0]
    else:
        api_key = auth[7:].strip()
    if not api_key:
        return None
    digest = hash_api_key(api_key.strip())
    with connect_db() as conn:
        row = conn.execute(
            """
            SELECT id, company_id, integration_id, name, provider
            FROM integration_api_keys
            WHERE key_hash = ? AND status = 'Activa'
            """,
            (digest,),
        ).fetchone()
        if row:
            conn.execute("UPDATE integration_api_keys SET last_used_at = ? WHERE id = ?", (now(), row["id"]))
            conn.execute(
                """
                INSERT INTO integration_logs (company_id, integration_id, event, detail, level, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (row["company_id"], row["integration_id"], "api_key.usada", f"Uso de API key {row['name']}", "info", now()),
            )
            conn.commit()
        return dict(row) if row else None


def make_external_guide():
    return f"TJX-{int(time.time())}{secrets.randbelow(9000) + 1000}"


def to_float(value, default=0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def normalize_external_order(data):
    shipping = data.get("shipping_address") or {}
    customer = data.get("customer") or {}
    line_items = data.get("line_items") or []
    first_line = line_items[0] if line_items else {}
    name = data.get("customer_name") or data.get("customer") or "Cliente externo"
    if isinstance(name, dict):
        name = " ".join(filter(None, [customer.get("first_name"), customer.get("last_name")])) or "Cliente externo"
    gateway_text = " ".join(
        str(value or "")
        for value in [
            data.get("payment"),
            data.get("gateway"),
            data.get("payment_gateway_names"),
            data.get("financial_status"),
            data.get("tags"),
        ]
    ).lower()
    is_cod = any(token in gateway_text for token in ["cod", "contraentrega", "contra entrega", "cash on delivery", "efectivo"])
    collect_amount = to_float(data.get("amount") if data.get("amount") is not None else data.get("total_price"), 0) if is_cod else 0
    return {
        "guide": data.get("guide") or make_external_guide(),
        "customer": data.get("customerName") or name or shipping.get("name") or "Cliente externo",
        "customer_id": data.get("customerId", ""),
        "phone": data.get("phone") or shipping.get("phone") or customer.get("phone") or "",
        "city": data.get("city") or shipping.get("city") or "Guayaquil",
        "sector": data.get("sector", ""),
        "address": data.get("address") or shipping.get("address1") or "",
        "reference": data.get("reference") or shipping.get("address2") or "",
        "courier": data.get("courier") or "Trajetix",
        "status": data.get("status") or "Picking",
        "amount": collect_amount,
        "payment": "COD" if is_cod else "Sin recaudo",
        "sku": data.get("sku") or first_line.get("sku") or first_line.get("title") or "Pedido externo",
        "external_ref": str(data.get("externalRef") or data.get("id") or data.get("order_number") or data.get("name") or "").strip(),
    }


def order_payload(row):
    payload = dict(row)
    payload["customerId"] = payload.pop("customer_id", "") or ""
    payload["originMode"] = payload.pop("origin_mode", "") or ""
    payload["senderWarehouse"] = payload.pop("sender_warehouse", "") or ""
    payload["senderName"] = payload.pop("sender_name", "") or ""
    payload["senderPhone"] = payload.pop("sender_phone", "") or ""
    payload["senderId"] = payload.pop("sender_id", "") or ""
    payload["senderCity"] = payload.pop("sender_city", "") or ""
    payload["senderAddress"] = payload.pop("sender_address", "") or ""
    payload["createdAt"] = payload.pop("created_at", "") or ""
    payload["courierGuide"] = payload.pop("courier_guide", "") or ""
    payload["externalRef"] = payload.pop("external_ref", "") or ""
    return payload


class TrajetixHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def do_OPTIONS(self):
        json_response(self, 200, {"ok": True})

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/api/health":
            json_response(self, 200, {"ok": True, "database": str(DB_PATH)})
            return
        if path == "/api/external/ping":
            api_key = authenticate_api_key(self)
            if not api_key:
                json_response(self, 401, {"error": "API key invalida o revocada"})
                return
            json_response(self, 200, {
                "ok": True,
                "company_id": api_key["company_id"],
                "integration_id": api_key.get("integration_id", ""),
                "provider": api_key.get("provider", ""),
                "message": "Conexion externa Trajetix activa"
            })
            return
        if path == "/api/public-track":
            guide = parse_qs(parsed.query).get("guide", [""])[0]
            with connect_db() as conn:
                order = conn.execute(
                    """
                    SELECT o.guide, o.customer, o.city, o.sector, o.address, o.courier,
                           o.status, o.amount, o.payment, o.sku, o.created_at,
                           c.courier_guide
                    FROM orders o
                    LEFT JOIN courier_guides c ON upper(c.order_guide) = upper(o.guide)
                    WHERE upper(o.guide) = upper(?) OR upper(c.courier_guide) = upper(?)
                    ORDER BY o.id DESC, c.id DESC
                    LIMIT 1
                    """,
                    (guide, guide),
                ).fetchone()
            if not order:
                json_response(self, 404, {"error": "Guia no encontrada"})
                return
            payload = dict(order)
            payload["courierGuide"] = payload.pop("courier_guide") or ""
            json_response(self, 200, {"order": payload})
            return
        if path == "/api/audit":
            session = current_session(self)
            if not session:
                json_response(self, 401, {"error": "No autenticado"})
                return
            with connect_db() as conn:
                rows = conn.execute(
                    """
                    SELECT action, entity, payload, created_at
                    FROM audit_log
                    WHERE company_id = ?
                    ORDER BY id DESC
                    LIMIT 100
                    """,
                    (session["company_id"],),
                ).fetchall()
            json_response(self, 200, {"audit": [dict(row) for row in rows]})
            return
        if path == "/api/orders":
            session = current_session(self)
            if not session:
                json_response(self, 401, {"error": "No autenticado"})
                return
            with connect_db() as conn:
                rows = conn.execute(
                    """
                    SELECT o.guide, o.customer, o.customer_id, o.phone, o.city, o.sector,
                           o.address, o.reference, o.origin_mode, o.sender_warehouse,
                           o.sender_name, o.sender_phone, o.sender_id, o.sender_city,
                           o.sender_address, o.courier, o.status, o.amount, o.payment,
                           o.sku, o.external_ref, o.created_at, c.courier_guide
                    FROM orders o
                    LEFT JOIN courier_guides c ON upper(c.order_guide) = upper(o.guide)
                    WHERE o.company_id = ?
                    ORDER BY o.id DESC
                    LIMIT 500
                    """,
                    (session["company_id"],),
                ).fetchall()
            json_response(self, 200, {"orders": [order_payload(row) for row in rows]})
            return
        if path == "/api/integration-logs":
            session = current_session(self)
            if not session:
                json_response(self, 401, {"error": "No autenticado"})
                return
            integration_id = parse_qs(parsed.query).get("integration_id", [""])[0]
            with connect_db() as conn:
                rows = conn.execute(
                    """
                    SELECT id, integration_id, event, detail, level, created_at
                    FROM integration_logs
                    WHERE company_id = ? AND (? = '' OR integration_id = ?)
                    ORDER BY id DESC
                    LIMIT 100
                    """,
                    (session["company_id"], integration_id, integration_id),
                ).fetchall()
            json_response(self, 200, {"logs": [dict(row) for row in rows]})
            return
        if path.startswith("/ref/"):
            self.path = "/index.html"
        super().do_GET()

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            data = read_json(self)
            if path == "/api/register":
                self.handle_register(data)
            elif path == "/api/login":
                self.handle_login(data)
            elif path == "/api/change-password":
                self.handle_change_password(data)
            elif path == "/api/profile":
                self.handle_profile(data)
            elif path == "/api/audit":
                self.handle_audit(data)
            elif path == "/api/orders":
                self.handle_order(data)
            elif path == "/api/integration-keys":
                self.handle_integration_key(data)
            elif path == "/api/external/orders":
                self.handle_external_order(data, "api.external")
            elif path == "/api/webhooks/shopify/orders":
                self.handle_external_order(data, "shopify.orders_create")
            elif path == "/api/warehouses":
                self.handle_warehouse(data)
            elif path == "/api/products":
                self.handle_product(data)
            elif path == "/api/sales":
                self.handle_sale(data)
            elif path == "/api/bank-accounts":
                self.handle_bank_account(data)
            elif path == "/api/withdrawals":
                self.handle_withdrawal(data)
            elif path == "/api/guides":
                self.handle_guide(data)
            else:
                json_response(self, 404, {"error": "Ruta no encontrada"})
        except Exception as exc:
            json_response(self, 500, {"error": str(exc)})

    def handle_register(self, data):
        required = ["name", "email", "password", "company"]
        if any(not data.get(field) for field in required):
            json_response(self, 400, {"error": "Faltan datos de registro"})
            return
        with connect_db() as conn:
            if conn.execute("SELECT 1 FROM users WHERE lower(email) = lower(?)", (data["email"],)).fetchone():
                json_response(self, 409, {"error": "Este email ya esta registrado"})
                return
            conn.execute(
                """
                INSERT INTO companies (legal_name, trade_name, tax_id, id_type, legal_form, vat_regime, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["company"],
                    data["company"],
                    data.get("tax_id", ""),
                    data.get("id_type", "RUC"),
                    data.get("legal_form", ""),
                    data.get("vat_regime", ""),
                    now(),
                ),
            )
            company_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            salt, pwd_hash = hash_password(data["password"])
            conn.execute(
                """
                INSERT INTO users
                (company_id, name, email, phone, password_salt, password_hash, role, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (company_id, data["name"], data["email"], data.get("phone", ""), salt, pwd_hash, "Administrador", "Activo", now()),
            )
            user_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            session = {"user_id": user_id, "company_id": company_id}
            audit(conn, session, "registro_usuario", "users", {"email": data["email"], "company": data["company"]})
            email_status = send_registration_email(conn, user_id, data["email"], data["name"])
            conn.commit()
            token = secrets.token_urlsafe(32)
            SESSIONS[token] = {"user_id": user_id, "company_id": company_id, "email": data["email"]}
            user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        json_response(self, 201, {"token": token, "user": public_user(user), "email_status": email_status})

    def handle_login(self, data):
        with connect_db() as conn:
            user = conn.execute("SELECT * FROM users WHERE lower(email) = lower(?)", (data.get("email", ""),)).fetchone()
            if not user or user["status"] != "Activo" or not verify_password(data.get("password", ""), user["password_salt"], user["password_hash"]):
                json_response(self, 401, {"error": "Email o contrasena incorrectos"})
                return
            token = secrets.token_urlsafe(32)
            SESSIONS[token] = {"user_id": user["id"], "company_id": user["company_id"], "email": user["email"]}
            audit(conn, SESSIONS[token], "inicio_sesion", "users", {"email": user["email"]})
            conn.commit()
        json_response(self, 200, {"token": token, "user": public_user(user)})

    def handle_change_password(self, data):
        session = current_session(self)
        if not session:
            json_response(self, 401, {"error": "No autenticado"})
            return
        current_password = data.get("current_password", "")
        new_password = data.get("new_password", "")
        if len(new_password) < 6:
            json_response(self, 400, {"error": "La nueva contrasena debe tener al menos 6 caracteres"})
            return
        with connect_db() as conn:
            user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
            if not user or not verify_password(current_password, user["password_salt"], user["password_hash"]):
                json_response(self, 400, {"error": "La contrasena actual no es correcta"})
                return
            salt, pwd_hash = hash_password(new_password)
            conn.execute(
                "UPDATE users SET password_salt = ?, password_hash = ? WHERE id = ?",
                (salt, pwd_hash, session["user_id"]),
            )
            audit(conn, session, "cambiar_contrasena", "users", {"email": user["email"]})
            conn.commit()
        json_response(self, 200, {"ok": True})

    def handle_profile(self, data):
        session = current_session(self)
        if not session:
            json_response(self, 401, {"error": "No autenticado"})
            return
        with connect_db() as conn:
            conn.execute(
                "UPDATE users SET name = ?, phone = ? WHERE id = ?",
                (data.get("name", ""), data.get("phone", ""), session["user_id"]),
            )
            conn.execute(
                """
                UPDATE companies
                SET legal_name = ?, trade_name = ?, tax_id = ?, id_type = ?
                WHERE id = ?
                """,
                (
                    data.get("legalName", ""),
                    data.get("legalName", ""),
                    data.get("taxId", ""),
                    data.get("idType", "RUC"),
                    session["company_id"],
                ),
            )
            audit(conn, session, "actualizar_perfil", "users", {"name": data.get("name", ""), "company": data.get("legalName", "")})
            conn.commit()
        json_response(self, 200, {"ok": True})

    def handle_audit(self, data):
        session = current_session(self)
        if not session:
            json_response(self, 401, {"error": "No autenticado"})
            return
        with connect_db() as conn:
            audit(conn, session, data.get("action", "accion_usuario"), data.get("entity"), data.get("payload"))
            conn.commit()
        json_response(self, 201, {"ok": True})

    def handle_order(self, data):
        session = current_session(self)
        if not session:
            json_response(self, 401, {"error": "No autenticado"})
            return
        guide = data.get("guide") or make_external_guide()
        with connect_db() as conn:
            conn.execute(
                """
                INSERT INTO orders
                (company_id, guide, customer, customer_id, phone, city, sector, address, reference,
                 origin_mode, sender_warehouse, sender_name, sender_phone, sender_id, sender_city,
                 sender_address, courier, status, amount, payment, sku, external_ref, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session["company_id"],
                    guide,
                    data.get("customer"),
                    data.get("customerId", ""),
                    data.get("phone", ""),
                    data.get("city"),
                    data.get("sector", ""),
                    data.get("address", ""),
                    data.get("reference", ""),
                    data.get("originMode", ""),
                    data.get("senderWarehouse", ""),
                    data.get("senderName", ""),
                    data.get("senderPhone", ""),
                    data.get("senderId", ""),
                    data.get("senderCity", ""),
                    data.get("senderAddress", ""),
                    data.get("courier"),
                    data.get("status", "Picking"),
                    float(data.get("amount", 0)),
                    data.get("payment", ""),
                    data.get("sku", ""),
                    data.get("externalRef", ""),
                    now(),
                ),
            )
            audit(conn, session, "crear_orden", "orders", data)
            conn.commit()
        json_response(self, 201, {"ok": True, "guide": guide})

    def handle_integration_key(self, data):
        session = current_session(self)
        if not session:
            json_response(self, 401, {"error": "No autenticado"})
            return
        secret = f"tjx_live_{secrets.token_urlsafe(32)}"
        prefix = secret[:16]
        with connect_db() as conn:
            conn.execute(
                """
                INSERT INTO integration_api_keys
                (company_id, integration_id, name, provider, prefix, key_hash, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session["company_id"],
                    data.get("integrationId", ""),
                    data.get("name", "Trajetix API key"),
                    data.get("provider", ""),
                    prefix,
                    hash_api_key(secret),
                    "Activa",
                    now(),
                ),
            )
            key_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            conn.execute(
                """
                INSERT INTO integration_logs (company_id, integration_id, event, detail, level, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (session["company_id"], data.get("integrationId", ""), "api_key.creada", f"API key creada para {data.get('name', 'integracion')}", "info", now()),
            )
            audit(conn, session, "crear_api_key", "integration_api_keys", {"integrationId": data.get("integrationId", ""), "prefix": prefix})
            conn.commit()
        json_response(self, 201, {"id": f"KEY-{key_id}", "prefix": prefix, "secret": secret})

    def handle_external_order(self, data, source):
        api_key = authenticate_api_key(self)
        if not api_key:
            json_response(self, 401, {"error": "API key invalida o revocada"})
            return
        order = normalize_external_order(data)
        if not order["customer"] or not order["phone"] or not order["city"] or not order["address"]:
            json_response(self, 400, {"error": "Cliente, telefono, ciudad y direccion son obligatorios"})
            return
        with connect_db() as conn:
            if order["external_ref"]:
                existing = conn.execute(
                    """
                    SELECT guide
                    FROM orders
                    WHERE company_id = ? AND external_ref = ?
                    ORDER BY id DESC
                    LIMIT 1
                    """,
                    (api_key["company_id"], order["external_ref"]),
                ).fetchone()
                if existing:
                    conn.execute(
                        """
                        INSERT INTO integration_logs (company_id, integration_id, event, detail, level, created_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (api_key["company_id"], api_key.get("integration_id", ""), "order.duplicated", f"Webhook repetido, se devolvio guia existente {existing['guide']}", "warn", now()),
                    )
                    conn.commit()
                    json_response(self, 200, {"ok": True, "guide": existing["guide"], "tracking_url": f"/#track={existing['guide']}", "duplicate": True})
                    return
            conn.execute(
                """
                INSERT INTO orders
                (company_id, guide, customer, customer_id, phone, city, sector, address, reference,
                 origin_mode, sender_warehouse, sender_name, sender_phone, sender_id, sender_city,
                 sender_address, courier, status, amount, payment, sku, external_ref, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    api_key["company_id"],
                    order["guide"],
                    order["customer"],
                    order["customer_id"],
                    order["phone"],
                    order["city"],
                    order["sector"],
                    order["address"],
                    order["reference"],
                    source,
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    order["courier"],
                    order["status"],
                    order["amount"],
                    order["payment"],
                    order["sku"],
                    order["external_ref"],
                    now(),
                ),
            )
            conn.execute(
                """
                INSERT INTO integration_logs (company_id, integration_id, event, detail, level, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (api_key["company_id"], api_key.get("integration_id", ""), "order.created", f"Guia {order['guide']} creada desde {source}", "info", now()),
            )
            conn.commit()
        json_response(self, 201, {"ok": True, "guide": order["guide"], "tracking_url": f"/#track={order['guide']}"})

    def handle_warehouse(self, data):
        session = current_session(self)
        if not session:
            json_response(self, 401, {"error": "No autenticado"})
            return
        with connect_db() as conn:
            conn.execute(
                """
                INSERT INTO warehouses
                (company_id, external_id, name, city, address, manager, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session["company_id"],
                    data.get("id", ""),
                    data.get("name", ""),
                    data.get("city", ""),
                    data.get("address", ""),
                    data.get("manager", ""),
                    now(),
                ),
            )
            audit(conn, session, "crear_bodega", "warehouses", data)
            conn.commit()
        json_response(self, 201, {"ok": True})

    def handle_product(self, data):
        session = current_session(self)
        if not session:
            json_response(self, 401, {"error": "No autenticado"})
            return
        sku = (data.get("sku") or "").strip().upper()
        if not sku or not data.get("product"):
            json_response(self, 400, {"error": "SKU y producto son obligatorios"})
            return
        with connect_db() as conn:
            conn.execute(
                """
                INSERT INTO products
                (company_id, sku, product, warehouse, location, available, reserved, min_stock, price,
                 weight_kg, length_cm, width_cm, height_cm, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(company_id, sku) DO UPDATE SET
                    product = excluded.product,
                    warehouse = excluded.warehouse,
                    location = excluded.location,
                    available = excluded.available,
                    reserved = excluded.reserved,
                    min_stock = excluded.min_stock,
                    price = excluded.price,
                    weight_kg = excluded.weight_kg,
                    length_cm = excluded.length_cm,
                    width_cm = excluded.width_cm,
                    height_cm = excluded.height_cm,
                    updated_at = excluded.updated_at
                """,
                (
                    session["company_id"],
                    sku,
                    data.get("product", ""),
                    data.get("warehouse", ""),
                    data.get("location", ""),
                    float(data.get("available", 0)),
                    float(data.get("reserved", 0)),
                    float(data.get("min", 0)),
                    float(data.get("price", 0)),
                    float(data.get("weightKg", 0)),
                    float(data.get("lengthCm", 0)),
                    float(data.get("widthCm", 0)),
                    float(data.get("heightCm", 0)),
                    now(),
                    now(),
                ),
            )
            audit(conn, session, "guardar_producto", "products", data)
            conn.commit()
        json_response(self, 201, {"ok": True})

    def handle_sale(self, data):
        session = current_session(self)
        if not session:
            json_response(self, 401, {"error": "No autenticado"})
            return
        with connect_db() as conn:
            conn.execute(
                """
                INSERT INTO sales (company_id, code, customer, payment, delivery, total, lines, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session["company_id"],
                    data.get("code", ""),
                    data.get("customer", ""),
                    data.get("payment", ""),
                    data.get("delivery", ""),
                    float(data.get("total", 0)),
                    json.dumps(data.get("lines", []), ensure_ascii=False),
                    now(),
                ),
            )
            audit(conn, session, "crear_venta", "sales", data)
            conn.commit()
        json_response(self, 201, {"ok": True})

    def handle_bank_account(self, data):
        session = current_session(self)
        if not session:
            json_response(self, 401, {"error": "No autenticado"})
            return
        with connect_db() as conn:
            conn.execute(
                """
                INSERT INTO bank_accounts
                (company_id, external_id, bank, account_type, account_number, masked, holder_name,
                 holder_id, status, validation_message, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session["company_id"],
                    data.get("id", ""),
                    data.get("bank", ""),
                    data.get("type", ""),
                    data.get("accountNumber", ""),
                    data.get("masked", ""),
                    data.get("holderName", ""),
                    data.get("holderId", ""),
                    data.get("status", "En revision"),
                    data.get("validationMessage", ""),
                    now(),
                ),
            )
            audit(conn, session, "guardar_cuenta_bancaria", "bank_accounts", {**data, "accountNumber": data.get("masked", "")})
            conn.commit()
        json_response(self, 201, {"ok": True})

    def handle_withdrawal(self, data):
        session = current_session(self)
        if not session:
            json_response(self, 401, {"error": "No autenticado"})
            return
        with connect_db() as conn:
            conn.execute(
                """
                INSERT INTO withdrawals
                (company_id, external_id, code, bank_account_id, bank_label, amount, reference, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session["company_id"],
                    data.get("id", ""),
                    data.get("code", ""),
                    data.get("bankAccountId", ""),
                    data.get("bankLabel", ""),
                    float(data.get("amount", 0)),
                    data.get("reference", ""),
                    data.get("status", "Solicitado"),
                    now(),
                ),
            )
            audit(conn, session, "solicitar_retiro", "withdrawals", data)
            conn.commit()
        json_response(self, 201, {"ok": True})

    def handle_guide(self, data):
        session = current_session(self)
        if not session:
            json_response(self, 401, {"error": "No autenticado"})
            return
        courier = data.get("courier", "")
        order_guide = data.get("order_guide", "")
        try:
            courier_guide = make_courier_guide(courier, order_guide)
        except ValueError as exc:
            json_response(self, 400, {"error": str(exc)})
            return
        label_url = f"/labels/{courier_guide}.pdf"
        with connect_db() as conn:
            conn.execute(
                """
                INSERT INTO courier_guides
                (company_id, order_guide, courier, courier_guide, label_url, status, payload, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session["company_id"],
                    order_guide,
                    courier,
                    courier_guide,
                    label_url,
                    "creada",
                    json.dumps(data, ensure_ascii=False),
                    now(),
                ),
            )
            audit(conn, session, "crear_guia_courier", "courier_guides", {"order_guide": order_guide, "courier": courier, "courier_guide": courier_guide})
            conn.commit()
        json_response(self, 201, {"courier_guide": courier_guide, "label_url": label_url, "status": "creada"})


if __name__ == "__main__":
    init_db()
    port = int(os.getenv("PORT", os.getenv("TRAJETIX_PORT", "8080")))
    host = os.getenv("HOST", "0.0.0.0")
    server = ThreadingHTTPServer((host, port), TrajetixHandler)
    print(f"Trajetix backend listo en http://{host}:{port}")
    print(f"Base de datos: {DB_PATH}")
    server.serve_forever()
