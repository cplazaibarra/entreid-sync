import os
import sys
import json
import time
import datetime
import threading
import requests
import pymysql
import hashlib
from flask import Flask, render_template, request, redirect, url_for, flash, session

app = Flask(__name__)
# Secure secret key
app.secret_key = "entraid_sync_secret_key_secure_2026"

CONFIG_PATH = "/app/config/config.json"
USERS_PATH = "/app/config/users.json"

# Default configuration structure
default_config = {
    "tenant_id": "",
    "client_id": "",
    "client_secret": "",
    "sync_frequency": 1,  # 1 = once a day, 2 = twice, etc. 0 = disabled
    "sync_hour": "03:00",  # HH:MM
    "last_status": "never",
    "last_run": "",
    "last_message": "Nunca se ha ejecutado la sincronización."
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

def do_sync():
    """Performs the synchronization between Entra ID and MariaDB."""
    if not sync_lock.acquire(blocking=False):
        return False, "La sincronización ya está en ejecución."

    config = load_config()
    db_conn = None
    
    tenant_id = config.get("tenant_id")
    client_id = config.get("client_id")
    client_secret = config.get("client_secret")

    if not tenant_id or not client_id or not client_secret:
        sync_lock.release()
        return False, "Error: Faltan credenciales de Entra ID por configurar."

    try:
        # 1. Fetch access token from Microsoft Entra ID
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
        
        # 2. Fetch users from Microsoft Graph API
        graph_url = "https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName,mail,givenName,surname,telephoneNumber,mobilePhone"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json"
        }
        
        users_response = requests.get(graph_url, headers=headers, timeout=15)
        if users_response.status_code != 200:
            raise Exception(f"Graph API query failed: {users_response.text}")
        
        entra_users = users_response.json().get("value", [])
        
        # 3. Connect to MariaDB (auth-db)
        db_conn = pymysql.connect(
            host="auth-db",
            user="privacyidea",
            password="db_pass_mquest_2026",
            database="privacyidea",
            autocommit=True
        )
        
        cursor = db_conn.cursor()
        
        # Ensure table exists and has groups column
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS entra_users (
                username VARCHAR(191) PRIMARY KEY,
                email VARCHAR(191),
                givenname VARCHAR(100),
                surname VARCHAR(100),
                phone VARCHAR(50),
                groups VARCHAR(500),
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("ALTER TABLE entra_users ADD COLUMN IF NOT EXISTS groups VARCHAR(500)")
        
        # 4. Perform synchronization (Upsert and optional Delete of stale users)
        current_usernames = []
        inserted = 0
        updated = 0
        
        for user in entra_users:
            email = user.get("userPrincipalName")
            if not email:
                continue
            username = email.replace('@', '_')
            user_id = user.get("id")
                
            mail_address = user.get("mail") or email
            givenname = user.get("givenName") or ""
            surname = user.get("surname") or ""
            phone = user.get("telephoneNumber") or user.get("mobilePhone") or ""
            
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
                                groups_list.append(g["displayName"].replace(" ", "_"))
                except Exception as ex:
                    print(f"Error fetching groups for {username}: {ex}", file=sys.stderr)
            
            groups_str = ",".join(groups_list)
            current_usernames.append(username)
            
            # Check if user already exists
            cursor.execute("SELECT email, givenname, surname, phone, groups FROM entra_users WHERE username = %s", (username,))
            row = cursor.fetchone()
            
            if row is None:
                # Insert
                cursor.execute("""
                    INSERT INTO entra_users (username, email, givenname, surname, phone, groups) 
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (username, mail_address, givenname, surname, phone, groups_str))
                inserted += 1
            else:
                # Check if values changed
                if row != (mail_address, givenname, surname, phone, groups_str):
                    cursor.execute("""
                        UPDATE entra_users 
                        SET email = %s, givenname = %s, surname = %s, phone = %s, groups = %s 
                        WHERE username = %s
                    """, (mail_address, givenname, surname, phone, groups_str, username))
                    updated += 1
                    
        # Delete users that are no longer in Entra ID
        deleted = 0
        if current_usernames:
            # Get count of users to delete
            format_strings = ','.join(['%s'] * len(current_usernames))
            cursor.execute(f"SELECT COUNT(*) FROM entra_users WHERE username NOT IN ({format_strings})", tuple(current_usernames))
            deleted = cursor.fetchone()[0]
            
            cursor.execute(f"DELETE FROM entra_users WHERE username NOT IN ({format_strings})", tuple(current_usernames))
        else:
            # If Entra returned 0 users, don't delete everything just in case of API failure,
            # unless we are sure. Let's keep it safe.
            pass

        timestamp_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        msg = f"Sincronización exitosa: {inserted} creados, {updated} actualizados, {deleted} eliminados. Total en DB: {len(current_usernames)}."
        
        config["last_status"] = "success"
        config["last_run"] = timestamp_str
        config["last_message"] = msg
        save_config(config)
        
        sync_lock.release()
        return True, msg
        
    except Exception as e:
        timestamp_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        error_msg = f"Error durante la sincronización: {str(e)}"
        print(error_msg, file=sys.stderr)
        
        config["last_status"] = "error"
        config["last_run"] = timestamp_str
        config["last_message"] = error_msg
        save_config(config)
        
        if db_conn:
            try:
                db_conn.close()
            except:
                pass
                
        sync_lock.release()
        return False, error_msg

def scheduler_loop():
    """Background thread to schedule sync runs."""
    print("Background scheduler thread started.", flush=True)
    # Give the DB time to boot on container start
    time.sleep(10)
    
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
                    do_sync()
                    
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
            config["tenant_id"] = request.form.get("tenant_id", "").strip()
            config["client_id"] = request.form.get("client_id", "").strip()
            # If client secret is empty, don't overwrite the existing one
            secret = request.form.get("client_secret", "").strip()
            if secret:
                config["client_secret"] = secret
                
            config["sync_frequency"] = int(request.form.get("sync_frequency", 1))
            config["sync_hour"] = request.form.get("sync_hour", "03:00").strip()
            
            save_config(config)
            flash("Configuración guardada correctamente.", "success")
            return redirect(url_for("index"))
            
        elif action == "sync_now":
            success, msg = do_sync()
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
                    flash(f"Usuario '{delete_username}' eliminado.", "success")
            return redirect(url_for("index"))

    return render_template("index.html", config=config, users=users, current_user=current_user, current_role=current_role)

if __name__ == "__main__":
    # Ensure default users are set up
    load_users()
    
    # Start background scheduler
    sched_thread = threading.Thread(target=scheduler_loop, daemon=True)
    sched_thread.start()
    
    # Start web server
    app.run(host="0.0.0.0", port=5500, debug=False)
