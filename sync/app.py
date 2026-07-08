import os
import sys
import json
import time
import datetime
import threading
import requests
import pymysql
import hashlib
import ldap3
from flask import Flask, render_template, request, redirect, url_for, flash, session

app = Flask(__name__)
# Secure secret key
app.secret_key = "entraid_sync_secret_key_secure_2026"

CONFIG_PATH = "/app/config/config.json"
USERS_PATH = "/app/config/users.json"
LOG_PATH = "/app/config/sync.log"

# Default configuration structure
default_config = {
    "tenant_id": "",
    "client_id": "",
    "client_secret": "",
    "sync_frequency": 1,  # 1 = once a day, 2 = twice, etc. 0 = disabled
    "sync_hour": "03:00",  # HH:MM
    "last_status": "never",
    "last_run": "",
    "last_message": "Nunca se ha ejecutado la sincronización.",
    "ldap_server": "openldap",
    "ldap_port": 389,
    "ldap_bind_dn": "cn=admin,dc=mquest,dc=local",
    "ldap_password": "admin_ldap_pass_2026",
    "ldap_base_dn": "dc=mquest,dc=local"
}

def load_config():
    if not os.path.exists(CONFIG_PATH):
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        save_config(default_config)
        return default_config
    try:
        with open(CONFIG_PATH, "r") as f:
            data = json.load(f)
            # Ensure all keys exist
            for k, v in default_config.items():
                if k not in data:
                    data[k] = v
            return data
    except Exception as e:
        print(f"Error loading config: {e}", file=sys.stderr)
        return default_config

def save_config(config_data):
    try:
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        with open(CONFIG_PATH, "w") as f:
            json.dump(config_data, f, indent=4)
    except Exception as e:
        print(f"Error saving config: {e}", file=sys.stderr)

# Hash helper
def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

# Load users database
def load_users():
    if not os.path.exists(USERS_PATH):
        os.makedirs(os.path.dirname(USERS_PATH), exist_ok=True)
        # Default user: admin / admin (write role)
        default_users = {
            "admin": {
                "password_hash": hash_password("admin"),
                "role": "write"
            }
        }
        save_users(default_users)
        return default_users
    try:
        with open(USERS_PATH, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading users: {e}", file=sys.stderr)
        return {}

def save_users(users_data):
    try:
        os.makedirs(os.path.dirname(USERS_PATH), exist_ok=True)
        with open(USERS_PATH, "w") as f:
            json.dump(users_data, f, indent=4)
    except Exception as e:
        print(f"Error saving users: {e}", file=sys.stderr)

# Write to log file
def write_log(msg):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"[{timestamp}] {msg}\n"
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        lines = []
        if os.path.exists(LOG_PATH):
            with open(LOG_PATH, "r") as f:
                lines = f.readlines()
        # Keep last 500 lines to bound file size
        lines = lines[-500:] + [log_line]
        with open(LOG_PATH, "w") as f:
            f.writelines(lines)
    except Exception as e:
        print(f"Error writing log: {e}", file=sys.stderr)

# Protect all routes
@app.before_request
def check_login():
    # Exclude login and static assets from protection
    if request.path == url_for('login') or request.path.startswith('/static'):
        return None
    if 'username' not in session:
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        users = load_users()
        if username in users:
            stored_user = users[username]
            if stored_user['password_hash'] == hash_password(password):
                session['username'] = username
                session['role'] = stored_user['role']
                return redirect(url_for('index'))
                
        flash('Nombre de usuario o contraseña incorrectos.')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Global lock for sync operations to avoid concurrent runs
sync_lock = threading.Lock()

def do_sync(is_manual=True):
    """Performs the synchronization between Entra ID and OpenLDAP."""
    if not sync_lock.acquire(blocking=False):
        return False, "La sincronización ya está en ejecución."

    trigger_type = "manual" if is_manual else "programada"
    write_log(f"Iniciando sincronización {trigger_type} hacia OpenLDAP...")
    
    config = load_config()
    
    tenant_id = config.get("tenant_id")
    client_id = config.get("client_id")
    client_secret = config.get("client_secret")

    ldap_server = config.get("ldap_server", "openldap")
    ldap_port = int(config.get("ldap_port", 389))
    ldap_bind_dn = config.get("ldap_bind_dn", "cn=admin,dc=mquest,dc=local")
    ldap_password = config.get("ldap_password", "admin_ldap_pass_2026")
    ldap_base_dn = config.get("ldap_base_dn", "dc=mquest,dc=local")

    if not tenant_id or not client_id or not client_secret:
        sync_lock.release()
        error_msg = "Error: Faltan credenciales de Entra ID por configurar."
        write_log(f"[ERROR] {error_msg}")
        return False, error_msg

    try:
        # 1. Fetch access token from Microsoft Entra ID
        write_log("Solicitando token de acceso a Entra ID...")
        token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        token_data = {
            "client_id": client_id,
            "scope": "https://graph.microsoft.com/.default",
            "client_secret": client_secret,
            "grant_type": "client_credentials"
        }
        
        token_response = requests.post(token_url, data=token_data, timeout=15)
        if token_response.status_code != 200:
            raise Exception(f"OAuth2 failed: {token_response.text}")
        
        access_token = token_response.json().get("access_token")
        write_log("Token de acceso obtenido correctamente.")
        
        # 2. Fetch users from Microsoft Graph API
        write_log("Consultando lista de usuarios en Microsoft Graph...")
        graph_url = "https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName,mail,givenName,surname,telephoneNumber,mobilePhone,displayName"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json"
        }
        
        users_response = requests.get(graph_url, headers=headers, timeout=15)
        if users_response.status_code != 200:
            raise Exception(f"Graph API query failed: {users_response.text}")
        
        entra_users = users_response.json().get("value", [])
        write_log(f"Se obtuvieron {len(entra_users)} usuarios desde Entra ID.")
        
        # 3. Connect to OpenLDAP server
        write_log(f"Conectando al servidor LDAP {ldap_server}:{ldap_port}...")
        server = ldap3.Server(ldap_server, port=ldap_port, get_info=ldap3.ALL)
        conn = ldap3.Connection(server, user=ldap_bind_dn, password=ldap_password, auto_bind=True)
        write_log("Conexión LDAP establecida con éxito.")

        # Ensure OUs exist
        users_ou = f"ou=Users,{ldap_base_dn}"
        groups_ou = f"ou=Groups,{ldap_base_dn}"
        
        conn.search(ldap_base_dn, "(ou=Users)", search_scope=ldap3.SUBTREE)
        if not conn.entries:
            conn.add(users_ou, 'organizationalUnit', {'ou': 'Users'})
            write_log("Creada OU en LDAP: ou=Users")
            
        conn.search(ldap_base_dn, "(ou=Groups)", search_scope=ldap3.SUBTREE)
        if not conn.entries:
            conn.add(groups_ou, 'organizationalUnit', {'ou': 'Groups'})
            write_log("Creada OU en LDAP: ou=Groups")

        # Get existing users in LDAP
        conn.search(users_ou, '(objectClass=inetOrgPerson)', search_scope=ldap3.SUBTREE, attributes=['cn', 'mail', 'givenName', 'sn', 'displayName'])
        ldap_users_dict = {entry.cn.value.lower(): entry.entry_dn for entry in conn.entries}
        
        # 4. Perform synchronization (Upsert and optional Delete of stale users)
        current_usernames = []
        inserted = 0
        updated = 0
        deleted = 0
        
        groups_map = {} # Maps group name to member DN list

        for user in entra_users:
            email = user.get("userPrincipalName")
            if not email:
                continue
            username = email.replace('@', '_')
            username_lower = username.lower()
            user_id = user.get("id")
                
            mail_address = user.get("mail") or email
            givenname = user.get("givenName") or ""
            surname = user.get("surname") or ""
            display = user.get("displayName") or username.split('_')[0]
            
            user_dn = f"cn={username},{users_ou}"
            current_usernames.append(username_lower)
            
            # Fetch groups for this user
            groups_list = []
            if user_id:
                try:
                    groups_url = f"https://graph.microsoft.com/v1.0/users/{user_id}/memberOf?$select=displayName,groupTypes"
                    groups_resp = requests.get(groups_url, headers=headers, timeout=10)
                    if groups_resp.status_code == 200:
                        for g in groups_resp.json().get("value", []):
                            if g.get("@odata.type") == "#microsoft.graph.group" and g.get("displayName"):
                                if "Unified" in g.get("groupTypes", []):
                                    continue
                                group_name = g["displayName"].replace(" ", "_")
                                groups_list.append(group_name)
                                if group_name not in groups_map:
                                    groups_map[group_name] = []
                                groups_map[group_name].append(user_dn)
                except Exception as ex:
                    print(f"Error fetching groups for {username}: {ex}", file=sys.stderr)
            
            # Add or update user in LDAP
            if username_lower not in ldap_users_dict:
                # Insert
                attrs = {
                    'cn': username,
                    'sn': surname if surname else username,
                    'givenName': givenname if givenname else username,
                    'displayName': display,
                    'mail': mail_address,
                    'userPassword': 'Mquest_pass_2026'
                }
                conn.add(user_dn, ['inetOrgPerson', 'organizationalPerson', 'person'], attrs)
                write_log(f"[CREAR] Usuario LDAP synced: {username} (Grupos: {', '.join(sorted(groups_list)) or 'Ninguno'})")
                inserted += 1
            else:
                # Update attributes
                existing_entry = None
                for entry in conn.entries:
                    if entry.entry_dn.lower() == user_dn.lower():
                        existing_entry = entry
                        break
                        
                needs_update = False
                modifications = {}
                if existing_entry:
                    if (existing_entry.mail.value or '') != mail_address:
                        modifications['mail'] = [(ldap3.MODIFY_REPLACE, [mail_address])]
                        needs_update = True
                    if (existing_entry.givenName.value or '') != givenname:
                        modifications['givenName'] = [(ldap3.MODIFY_REPLACE, [givenname])]
                        needs_update = True
                    if (existing_entry.sn.value or '') != surname:
                        modifications['sn'] = [(ldap3.MODIFY_REPLACE, [surname if surname else username])]
                        needs_update = True
                    if (existing_entry.displayName.value or '') != display:
                        modifications['displayName'] = [(ldap3.MODIFY_REPLACE, [display])]
                        needs_update = True
                        
                if needs_update:
                    conn.modify(user_dn, modifications)
                    write_log(f"[ACTUALIZAR] Usuario LDAP synced: {username} (Grupos: {', '.join(sorted(groups_list)) or 'Ninguno'})")
                    updated += 1

        # Delete users that are no longer in Entra ID
        for cn_lower, dn in ldap_users_dict.items():
            if cn_lower not in current_usernames:
                conn.delete(dn)
                write_log(f"[ELIMINAR] Usuario LDAP obsoleto: {dn}")
                deleted += 1

        # 5. Synchronize Groups in LDAP
        conn.search(groups_ou, '(objectClass=groupOfNames)', search_scope=ldap3.SUBTREE, attributes=['cn', 'member'])
        existing_groups = {entry.cn.value.lower(): (entry.entry_dn, entry.member.values) for entry in conn.entries}
        
        for group_name, members in groups_map.items():
            group_dn = f"cn={group_name},{groups_ou}"
            group_name_lower = group_name.lower()
            
            # groupOfNames requires at least one member
            if not members:
                members = [ldap_bind_dn]
                
            if group_name_lower not in existing_groups:
                attrs = {
                    'cn': group_name,
                    'member': members
                }
                conn.add(group_dn, ['groupOfNames'], attrs)
                write_log(f"[GRUPO-CREAR] Grupo LDAP synced: {group_name} ({len(members)} miembros)")
            else:
                existing_dn, existing_members = existing_groups[group_name_lower]
                set_existing = {m.lower() for m in existing_members}
                set_new = {m.lower() for m in members}
                
                if set_existing != set_new:
                    conn.modify(group_dn, {'member': [(ldap3.MODIFY_REPLACE, members)]})
                    write_log(f"[GRUPO-ACTUALIZAR] Grupo LDAP synced: {group_name} ({len(members)} miembros)")

        conn.unbind()
        
        timestamp_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        msg = f"Sincronización LDAP exitosa: {inserted} creados, {updated} actualizados, {deleted} eliminados. Total en Directorio: {len(current_usernames)}."
        write_log(msg)
        
        config["last_status"] = "success"
        config["last_run"] = timestamp_str
        config["last_message"] = msg
        save_config(config)
        
        sync_lock.release()
        return True, msg
        
    except Exception as e:
        timestamp_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        error_msg = f"Error durante la sincronización LDAP: {str(e)}"
        print(error_msg, file=sys.stderr)
        write_log(f"[ERROR] {error_msg}")
        
        config["last_status"] = "error"
        config["last_run"] = timestamp_str
        config["last_message"] = error_msg
        save_config(config)
        
        sync_lock.release()
        return False, error_msg

def scheduler_loop():
    """Background thread to schedule sync runs."""
    print("Background scheduler thread started.", flush=True)
    # Give the DB/LDAP time to boot on container start
    time.sleep(15)
    
    while True:
        try:
            config = load_config()
            freq = int(config.get("sync_frequency", 1))
            sync_hour = config.get("sync_hour", "03:00")
            
            if freq > 0:
                now = datetime.datetime.now()
                last_run_str = config.get("last_run", "")
                
                # Parse last run time
                last_run_time = 0
                if last_run_str:
                    try:
                        dt = datetime.datetime.strptime(last_run_str, "%Y-%m-%d %H:%M:%S")
                        last_run_time = dt.timestamp()
                    except ValueError:
                        pass
                
                current_time = time.time()
                should_run = False
                
                if freq == 1:
                    # Once a day at specific hour
                    hour_str = now.strftime("%H:%M")
                    if hour_str == sync_hour:
                        # Prevent duplicate runs in the same minute
                        if current_time - last_run_time > 3600:
                            should_run = True
                else:
                    # N times a day
                    interval_seconds = (24.0 / freq) * 3600
                    if current_time - last_run_time >= interval_seconds:
                        should_run = True
                
                if should_run:
                    print(f"Triggering scheduled sync at {now.strftime('%Y-%m-%d %H:%M:%S')}", flush=True)
                    do_sync(is_manual=False)
                    
        except Exception as e:
            print(f"Error in scheduler loop: {e}", file=sys.stderr)
            
        time.sleep(30)  # Check every 30 seconds

@app.route("/", methods=["GET", "POST"])
def index():
    config = load_config()
    users = load_users()
    
    current_user = session.get('username')
    current_role = session.get('role', 'read')
    
    if request.method == "POST":
        action = request.form.get("action")
        
        # Enforce WRITE role permissions for modifying actions
        if current_role != 'write':
            flash("Acceso denegado: se requieren permisos de escritura.", "error")
            return redirect(url_for("index"))
            
        if action == "save":
            submit_action = request.form.get("submit_action", "save")
            
            tenant_id = request.form.get("tenant_id", "").strip()
            client_id = request.form.get("client_id", "").strip()
            secret = request.form.get("client_secret", "").strip()
            if not secret:
                secret = config.get("client_secret", "")
                
            ldap_server = request.form.get("ldap_server", "openldap").strip()
            ldap_port = int(request.form.get("ldap_port", 389))
            ldap_bind_dn = request.form.get("ldap_bind_dn", "").strip()
            ldap_password = request.form.get("ldap_password", "").strip()
            if not ldap_password:
                ldap_password = config.get("ldap_password", "")
            ldap_base_dn = request.form.get("ldap_base_dn", "").strip()

            if submit_action == "test":
                if not tenant_id or not client_id or not secret:
                    flash("Error: Debe completar todos los campos de Entra ID para probar la conexión.", "error")
                    return redirect(url_for("index"))
                write_log("Iniciando prueba de conexión con Microsoft Entra ID...")
                try:
                    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
                    token_data = {
                        "client_id": client_id,
                        "scope": "https://graph.microsoft.com/.default",
                        "client_secret": secret,
                        "grant_type": "client_credentials"
                    }
                    token_response = requests.post(token_url, data=token_data, timeout=10)
                    if token_response.status_code == 200:
                        write_log("¡Prueba de conexión exitosa! Las credenciales de Microsoft Entra ID son válidas.")
                        flash("¡Conexión Exitosa! Las credenciales de Microsoft Entra ID son válidas.", "success")
                    else:
                        try:
                            err_desc = token_response.json().get("error_description", token_response.text)
                        except:
                            err_desc = token_response.text
                        write_log(f"[ERROR-CONEXION] Fallo en la prueba de conexión: {err_desc}")
                        flash(f"Error de conexión: {err_desc}", "error")
                except Exception as e:
                    write_log(f"[ERROR-CONEXION] Fallo en la prueba de conexión: {str(e)}")
                    flash(f"Error al conectar con Microsoft Graph: {str(e)}", "error")
                return redirect(url_for("index"))
                
            # Otherwise, save the configuration
            config["tenant_id"] = tenant_id
            config["client_id"] = client_id
            if request.form.get("client_secret", "").strip():
                config["client_secret"] = request.form.get("client_secret", "").strip()
                
            config["sync_frequency"] = int(request.form.get("sync_frequency", 1))
            config["sync_hour"] = request.form.get("sync_hour", "03:00").strip()
            
            # Save LDAP parameters
            config["ldap_server"] = ldap_server
            config["ldap_port"] = ldap_port
            config["ldap_bind_dn"] = ldap_bind_dn
            config["ldap_password"] = ldap_password
            config["ldap_base_dn"] = ldap_base_dn

            save_config(config)
            write_log("Configuración de sincronización guardada por el administrador.")
            flash("Configuración guardada correctamente.", "success")
            return redirect(url_for("index"))
            
        elif action == "sync_now":
            success, msg = do_sync(is_manual=True)
            if success:
                flash(msg, "success")
            else:
                flash(msg, "error")
            return redirect(url_for("index"))
            
        elif action == "add_user":
            new_username = request.form.get("new_username", "").strip().lower()
            new_password = request.form.get("new_password", "")
            new_role = request.form.get("new_role", "read")
            
            if not new_username or not new_password:
                flash("El usuario y la contraseña son obligatorios.", "error")
            elif new_username in users:
                flash("El usuario ya existe.", "error")
            else:
                users[new_username] = {
                    "password_hash": hash_password(new_password),
                    "role": new_role
                }
                save_users(users)
                write_log(f"Nuevo usuario '{new_username}' creado con rol '{new_role}'.")
                flash(f"Usuario '{new_username}' creado con éxito.", "success")
            return redirect(url_for("index"))
            
        elif action == "delete_user":
            delete_username = request.form.get("delete_username", "").strip().lower()
            if delete_username == current_user:
                flash("No puedes eliminar tu propio usuario activo.", "error")
            elif delete_username in users:
                # Ensure we don't delete the last administrator
                write_users = [u for u, d in users.items() if d['role'] == 'write' and u != delete_username]
                if not write_users:
                    flash("No se puede eliminar el último usuario con rol de escritura.", "error")
                else:
                    del users[delete_username]
                    save_users(users)
                    write_log(f"Usuario '{delete_username}' eliminado por el administrador.")
                    flash(f"Usuario '{delete_username}' eliminado.", "success")
            return redirect(url_for("index"))

    return render_template("index.html", config=config, users=users, current_user=current_user, current_role=current_role)

@app.route("/api/logs")
def get_logs():
    if not os.path.exists(LOG_PATH):
        return "No hay registros en la bitácora todavía."
    try:
        with open(LOG_PATH, "r") as f:
            return f.read()
    except Exception as e:
        return f"Error leyendo bitácora: {str(e)}"

@app.route("/api/logs/clear", methods=["POST"])
def clear_logs():
    current_role = session.get('role', 'read')
    if current_role != 'write':
        return "Acceso denegado", 403
    try:
        if os.path.exists(LOG_PATH):
            os.remove(LOG_PATH)
        write_log("Bitácora de sincronización limpiada por el administrador.")
        return "success"
    except Exception as e:
        return str(e), 500

if __name__ == "__main__":
    # Ensure default users are set up
    load_users()
    
    # Start background scheduler
    sched_thread = threading.Thread(target=scheduler_loop, daemon=True)
    sched_thread.start()
    
    # Start web server
    app.run(host="0.0.0.0", port=5500, debug=False)
