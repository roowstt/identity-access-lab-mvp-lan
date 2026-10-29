import hmac
import os
import re
import secrets
import sqlite3
from datetime import timedelta
from functools import wraps
from urllib.parse import quote, urlparse

import requests
from authlib.integrations.flask_client import OAuth
from flask import Flask, abort, jsonify, redirect, render_template, request, session

from app.store import Store

DEMO_PASSWORD_VARS = {
    "ingeniero@example.test": "DEMO_PASSWORD_ENGINEER",
    "auditor@example.test": "DEMO_PASSWORD_AUDITOR",
    "admin@example.test": "DEMO_PASSWORD_ADMIN",
    "rrhh@example.test": "DEMO_PASSWORD_RRHH",
    "ti@example.test": "DEMO_PASSWORD_TI",
    "iam@example.test": "DEMO_PASSWORD_IAM",
    "soc-auditoria@example.test": "DEMO_PASSWORD_SOC_AUDITORIA",
    "seguridad-fisica@example.test": "DEMO_PASSWORD_SEGURIDAD_FISICA",
}


def create_app():
    app = Flask(__name__)
    app.secret_key = os.environ["APP_SECRET"]
    app.config.update(
        SESSION_COOKIE_NAME="identity_access_lab_session",
        SESSION_COOKIE_SECURE=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
        MAX_CONTENT_LENGTH=65536,
    )
    base = os.environ.get("APP_BASE_URL", "http://localhost:8000").rstrip("/")
    scim_token = os.environ["SCIM_TOKEN"]
    if len(app.secret_key) < 32 or len(scim_token) < 32 or not base.startswith(("http://localhost", "http://192.168.", "http://10.", "http://172.", "https://")):
        raise RuntimeError("Configura secretos de 32+ caracteres y APP_BASE_URL localhost HTTP o HTTPS")
    app.config["SESSION_COOKIE_SECURE"] = base.startswith("https://")
    store = Store(os.environ.get("APP_DB", "data/lab.sqlite"))
    oauth = OAuth(app)
    oauth.register(
        name="idp",
        client_id=os.environ["OIDC_CLIENT_ID"],
        client_secret=os.environ["OIDC_CLIENT_SECRET"],
        server_metadata_url=os.environ["OIDC_METADATA_URL"],
        client_kwargs={"scope": "openid profile email"},
    )

    # --- Acceso con badge NFC (opcional) ---
    nfc_enabled = os.environ.get("NFC_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    nfc_token = os.environ.get("NFC_BRIDGE_TOKEN", "")
    nfc_login_username = os.environ.get("NFC_LOGIN_USERNAME", "").strip().lower()
    nfc_login_password = os.environ.get("NFC_LOGIN_PASSWORD", "")
    nfc_tap_ttl = max(5, int(os.environ.get("NFC_TAP_TTL_SECONDS", "15")))
    if nfc_enabled and len(nfc_token) < 32:
        raise RuntimeError("NFC_BRIDGE_TOKEN debe tener 32 caracteres o más para habilitar el acceso NFC")

    def badge_credentials(username):
        """Devuelve (usuario, contraseña) guardados en el entorno para el titular del badge."""
        username = str(username or "").strip().lower()
        if not username:
            return None
        if username == nfc_login_username and nfc_login_password:
            return username, nfc_login_password
        explicit = "NFC_PASSWORD_" + re.sub(r"[^A-Z0-9]+", "_", username.upper()).strip("_")
        if os.environ.get(explicit):
            return username, os.environ[explicit]
        demo_var = DEMO_PASSWORD_VARS.get(username)
        if demo_var and os.environ.get(demo_var):
            return username, os.environ[demo_var]
        return None

    def badge_sign_in(username):
        """Abre sesión en Keycloak con las credenciales guardadas del usuario del badge."""
        credentials = badge_credentials(username)
        if not credentials:
            return None, "No hay credenciales guardadas para " + username
        metadata_url = os.environ.get("OIDC_INTERNAL_METADATA_URL") or os.environ["OIDC_METADATA_URL"]
        metadata = {}
        try:
            metadata = requests.get(metadata_url, timeout=5).json()
        except (requests.RequestException, ValueError):
            metadata = {}
        # La metadata declara los endpoints con el host publico (localhost:8081), que no
        # resuelve dentro de la red de Compose. Se usan las direcciones internas, igual que
        # hace el proxy /oidc/metadata.
        internal_base = os.environ.get("OIDC_INTERNAL_BASE_URL", "").rstrip("/")
        token_endpoint = internal_base + "/token" if internal_base else metadata.get("token_endpoint")
        userinfo_endpoint = internal_base + "/userinfo" if internal_base else metadata.get("userinfo_endpoint")
        if not token_endpoint:
            return None, "El proveedor OIDC local no expone un endpoint de token"
        try:
            token_response = requests.post(
                token_endpoint,
                data={
                    "grant_type": "password",
                    "client_id": os.environ["OIDC_CLIENT_ID"],
                    "client_secret": os.environ["OIDC_CLIENT_SECRET"],
                    "username": credentials[0],
                    "password": credentials[1],
                    "scope": "openid profile email",
                },
                timeout=10,
            )
        except (requests.RequestException, ValueError, KeyError) as error:
            app.logger.warning("Fallo al pedir token del badge: %s", error)
            return None, "El proveedor OIDC local no está disponible"
        if not token_response.ok:
            return None, "El proveedor OIDC local rechazó el acceso del badge"
        payload = token_response.json()
        access_token = payload.get("access_token")
        if not access_token:
            return None, "El proveedor OIDC local no devolvió token"
        identity = payload.get("userinfo") or {}
        if not userinfo_endpoint:
            userinfo_endpoint = metadata.get("userinfo_endpoint")
        if userinfo_endpoint:
            try:
                userinfo = requests.get(userinfo_endpoint, headers={"Authorization": "Bearer " + access_token}, timeout=10)
                if userinfo.ok:
                    identity = userinfo.json()
            except (requests.RequestException, ValueError):
                identity = payload.get("userinfo") or {}
        subject = identity.get("sub")
        email = identity.get("email")
        if not subject or not email:
            return None, "El proveedor OIDC local devolvió una identidad incompleta"
        user = store.by_name(email)
        if not user or not user.get("active"):
            return None, "El usuario local no está disponible"
        if not store.bind_identity(user["id"], str(subject)):
            return None, "La identidad ya está vinculada a otra cuenta"
        session.clear()
        session["uid"] = user["id"]
        session["csrf"] = secrets.token_urlsafe(32)
        session.permanent = True
        store.event(user["id"], "LOGIN_NFC", "PERMITIDO")
        return user, None

    def scim_auth(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            expected = "Bearer " + scim_token
            if not hmac.compare_digest(request.headers.get("Authorization", ""), expected):
                return scim_error("No autorizado", 401)
            return fn(*args, **kwargs)
        return wrapped

    def require(action):
        def decorate(fn):
            @wraps(fn)
            def wrapped(*args, **kwargs):
                uid = session.get("uid")
                if not uid:
                    return redirect("/login")
                if not store.permitted(uid, action):
                    store.event(uid, action, "DENEGADO")
                    abort(403)
                if request.method == "POST" and not hmac.compare_digest(request.form.get("csrf", ""), session.get("csrf", "")):
                    abort(400)
                store.event(uid, action, "PERMITIDO")
                return fn(*args, **kwargs)
            return wrapped
        return decorate

    def scim_error(detail, status):
        return jsonify({"schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"], "detail": detail, "status": str(status)}), status

    @app.get("/health")
    def health():
        return jsonify(status="ok")

    @app.get("/oidc/metadata")
    def oidc_metadata():
        """Descubre Keycloak desde la red Docker y usa URL internas para llamadas del servidor."""
        url = os.environ.get("OIDC_INTERNAL_METADATA_URL")
        if not url:
            return scim_error("Proxy de metadata local no configurado", 404)
        try:
            data = requests.get(url, timeout=5).json()
        except requests.RequestException:
            return jsonify(error="Proveedor OIDC local no disponible"), 503
        internal = os.environ.get("OIDC_INTERNAL_BASE_URL", "").rstrip("/")
        for key, suffix in (("token_endpoint", "/token"), ("userinfo_endpoint", "/userinfo"), ("jwks_uri", "/certs")):
            data[key] = internal + suffix
        return jsonify(data)

    @app.get("/")
    def home():
        uid = session.get("uid")
        user = store.get(uid) if uid else None
        if user and not user.get("active"):
            session.clear()
            user = None
        if not user:
            session.setdefault("csrf", secrets.token_urlsafe(32))
            return render_template("dashboard.html", title="Acceso", page="login", user=None, users=[], csrf=session["csrf"], nfc_enabled=nfc_enabled)
        session.setdefault("csrf", secrets.token_urlsafe(32))
        return render_template("dashboard.html", title="Resumen", page="home", user=user, users=[], csrf=session["csrf"], nfc_enabled=nfc_enabled)

    @app.get("/login")
    def login():
        if request.host != urlparse(base).netloc:
            return redirect(base + "/login")
        return oauth.idp.authorize_redirect(base + "/auth/callback", prompt="login")

    @app.get("/auth/callback")
    def callback():
        try:
            token = oauth.idp.authorize_access_token()
            identity = token.get("userinfo") or oauth.idp.userinfo(token=token)
            if not identity or not identity.get("sub") or not identity.get("email"):
                abort(403)
            user = store.by_name(identity["email"])
            if not user or not user.get("active") or not store.bind_identity(user["id"], str(identity["sub"])):
                store.event("desconocido", "LOGIN", "DENEGADO")
                abort(403)
            session.clear()
            session["uid"] = user["id"]
            session["csrf"] = secrets.token_urlsafe(32)
            session.permanent = True
            store.event(user["id"], "LOGIN_OIDC", "PERMITIDO")
            return redirect("/")
        except Exception:
            app.logger.exception("Inicio OIDC rechazado o incompleto")
            abort(403)

    @app.get("/consulta")
    @require("consulta")
    def consultation():
        return render_template("dashboard.html", title="Consulta", page="consultation", user=store.get(session["uid"]), users=[], csrf=session.get("csrf"))

    @app.post("/mantenimiento")
    @require("mantenimiento")
    def maintenance():
        return render_template("dashboard.html", title="Mantenimiento", page="maintenance", user=store.get(session["uid"]), users=[], csrf=session.get("csrf"))

    @app.post("/admin")
    @require("admin")
    def administration():
        return render_template("dashboard.html", title="Administración", page="administration", user=store.get(session["uid"]), users=[], csrf=session.get("csrf"))

    @app.get("/registros")
    @require("registros")
    def records():
        return render_template("dashboard.html", title="Bitácora", page="events", user=store.get(session["uid"]), users=[], events=store.events(), csrf=session.get("csrf"))

    @app.get("/turno")
    def shift_change():
        user = store.get(session["uid"]) if session.get("uid") else None
        return render_template(
            "cambio_turno.html",
            title="Cambio de Turno",
            page="turno",
            user=user,
            csrf=session.get("csrf"),
        )

    @app.route("/api/turno", methods=["GET", "POST"])
    def api_shift_change():
        if request.method == "POST":
            payload = request.get_json(silent=True) or request.form.to_dict() or {}
            operator = str(payload.get("operator", "Operador SOC")).strip()
            shift = str(payload.get("shift", "tarde")).strip().lower()
            status = str(payload.get("status", "success")).strip().lower()
            cams = payload.get("cams", [])
            cams_str = ", ".join(cams) if isinstance(cams, list) else str(cams)
            action_desc = f"TURNO_{shift.upper()}"
            if cams_str:
                action_desc += f" [CAMS: {cams_str}]"
            result_label = "CONFORME" if status == "success" else ("ADVERTENCIA" if status == "warning" else "INCIDENCIA")
            store.event(operator, action_desc, result_label)
            return jsonify(ok=True)
        return jsonify(events=store.events())

    @app.post("/nfc/tap")
    def nfc_tap():
        """El puente NFC del host envía el UID leído; la app decide si la tarjeta está autorizada."""
        if not nfc_enabled:
            return jsonify(error="El acceso NFC está deshabilitado"), 404
        if not hmac.compare_digest(request.headers.get("Authorization", ""), "Bearer " + nfc_token):
            return jsonify(error="No autorizado"), 401
        payload = request.get_json(silent=True) or {}
        uid = str(payload.get("uid", ""))
        card = store.card(uid)
        if not card:
            store.event("nfc:" + (uid or "?"), "NFC_TAP", "DENEGADO")
            return jsonify(error="Tarjeta no registrada"), 403
        user = store.by_name(card["username"])
        if not user or not user.get("active"):
            store.event("nfc:" + card["uid"], "NFC_TAP", "DENEGADO")
            return jsonify(error="Usuario no disponible"), 403
        store.record_tap(card["uid"], card["username"], str(payload.get("source", "bridge")))
        return jsonify(accepted=True, user=card["username"])

    @app.post("/nfc/poll")
    def nfc_poll():
        """El navegador pregunta si hay un toque pendiente y, si lo hay, abre sesión con el badge."""
        if not nfc_enabled:
            return jsonify(login=False)
        payload = request.get_json(silent=True) or {}
        csrf = str(payload.get("csrf", ""))
        if not hmac.compare_digest(csrf.encode("utf-8"), str(session.get("csrf", "")).encode("utf-8")):
            return jsonify(error="Token CSRF inválido"), 400
        tap = store.claim_tap(nfc_tap_ttl)
        if not tap:
            return jsonify(login=False)
        if session.get("uid"):
            # Ya hay una sesion abierta: el toque se descarta en lugar de guardarse, para
            # que no reabra el acceso por si solo cuando el usuario cierre la sesion.
            store.event("nfc:" + tap["uid"], "NFC_TAP_DESCARTADO", "OK")
            return jsonify(login=False)
        user, error = badge_sign_in(tap["username"])
        if not user:
            store.event("nfc:" + tap["uid"], "LOGIN_NFC", "DENEGADO")
            return jsonify(login=False, error=error), 401
        return jsonify(login=True, user=user["userName"])

    @app.get("/nfc")
    @require("admin")
    def nfc_admin():
        return render_template(
            "dashboard.html",
            title="Badge NFC",
            page="nfc",
            user=store.get(session["uid"]),
            users=store.all(),
            cards=store.cards(),
            csrf=session.get("csrf"),
            nfc_enabled=nfc_enabled,
            nfc_ttl=nfc_tap_ttl,
        )

    @app.post("/nfc/tarjetas")
    @require("admin")
    def nfc_card_create():
        try:
            store.register_card(request.form.get("uid", ""), request.form.get("username", ""), request.form.get("label", ""))
        except ValueError as error:
            return redirect("/nfc?error=" + quote(str(error)))
        return redirect("/nfc")

    @app.post("/nfc/tarjetas/eliminar")
    @require("admin")
    def nfc_card_delete():
        store.remove_card(request.form.get("uid", ""))
        return redirect("/nfc")

    @app.get("/admin/usuarios")
    @require("admin")
    def admin_users():
        return render_template("dashboard.html", title="Usuarios", page="users", user=store.get(session["uid"]), users=store.all(), csrf=session["csrf"])

    @app.post("/logout")
    def logout():
        if not session.get("uid") or not hmac.compare_digest(request.form.get("csrf", ""), session.get("csrf", "")):
            abort(400)
        store.event(session["uid"], "LOGOUT_APP", "OK")
        # Los toques leidos antes del cierre se descartan: si no quedaran guardados, la
        # pantalla de acceso los consumiria al reiniciar el polling y volveria a abrir
        # sesion sin que el usuario pase la tarjeta de nuevo.
        store.clear_taps()
        session.clear()
        return redirect("/")

    @app.route("/scim/v2/Users", methods=["GET", "POST"])
    @scim_auth
    def scim_users():
        if request.method == "GET":
            query = request.args.get("filter", "")
            if query:
                match = re.fullmatch(r'userName\s+eq\s+"([^"]+)"', query, re.IGNORECASE)
                if not match:
                    return scim_error('Solo se admite userName eq "correo"', 400)
                found = store.by_name(match.group(1))
                resources = [found] if found else []
            else:
                resources = store.all()
            start = max(1, request.args.get("startIndex", 1, type=int))
            count = max(0, min(100, request.args.get("count", 100, type=int)))
            page = resources[start - 1:start - 1 + count]
            return jsonify(schemas=["urn:ietf:params:scim:api:messages:2.0:ListResponse"], totalResults=len(resources), startIndex=start, itemsPerPage=len(page), Resources=page)
        try:
            result = store.save(request.get_json(force=True))
            response = jsonify(result)
            response.status_code = 201
            response.headers["Location"] = base + "/scim/v2/Users/" + result["id"]
            return response
        except sqlite3.IntegrityError:
            return scim_error("Usuario duplicado", 409)
        except (ValueError, TypeError):
            return scim_error("Datos no válidos", 400)

    @app.route("/scim/v2/Users/<user_id>", methods=["GET", "PUT", "PATCH", "DELETE"])
    @scim_auth
    def scim_user(user_id):
        current = store.get(user_id)
        if not current:
            return scim_error("Usuario no encontrado", 404)
        if request.method == "GET":
            return jsonify(current)
        if request.method == "DELETE":
            store.deactivate(user_id)
            return "", 204
        try:
            payload = request.get_json(force=True)
            if request.method == "PATCH":
                changes = {}
                if not isinstance(payload, dict) or not isinstance(payload.get("Operations"), list):
                    return scim_error("PATCH requiere Operations", 400)
                for operation in payload["Operations"]:
                    if not isinstance(operation, dict) or operation.get("op", "").lower() not in ("replace", "add"):
                        return scim_error("Operación PATCH no admitida", 400)
                    path = operation.get("path")
                    value = operation.get("value")
                    if path in ("active", "title", "userName"):
                        changes[path] = value
                    elif path is None and isinstance(value, dict):
                        changes.update(value)
                    else:
                        return scim_error("Ruta PATCH no admitida", 400)
                payload = changes
            return jsonify(store.save(payload, user_id))
        except sqlite3.IntegrityError:
            return scim_error("Usuario duplicado", 409)
        except (ValueError, TypeError):
            return scim_error("Datos no válidos", 400)

    @app.get("/scim/v2/Groups")
    @scim_auth
    def scim_groups():
        return jsonify(schemas=["urn:ietf:params:scim:api:messages:2.0:ListResponse"], totalResults=0, startIndex=1, itemsPerPage=0, Resources=[])

    return app


app = create_app()
