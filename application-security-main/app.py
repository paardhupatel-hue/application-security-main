import os
import re
import sqlite3
from datetime import datetime, timedelta
from functools import wraps
import bcrypt
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    abort,
    jsonify
)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'cybersec-app-sec-prototype-secret-key-2026')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'app_sec.db')


# ==========================================
# DATABASE INITIALIZATION & HELPERS
# ==========================================
def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout = 30000;")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Security Audit Logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            event_type TEXT NOT NULL,
            username TEXT,
            ip_address TEXT,
            details TEXT
        )
    ''')
    conn.commit()

    # Seed default demonstration accounts if not present
    seed_users = [
        ('admin', 'admin@cybersec.local', 'Admin@12345!', 'admin'),
        ('johndoe', 'john.doe@example.com', 'User@12345!', 'user')
    ]

    for username, email, raw_password, role in seed_users:
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if not cursor.fetchone():
            salt = bcrypt.gensalt()
            hashed_pw = bcrypt.hashpw(raw_password.encode('utf-8'), salt).decode('utf-8')
            cursor.execute(
                "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
                (username, email, hashed_pw, role)
            )
            log_security_event('SEED_ACCOUNT_CREATED', username, '127.0.0.1', f'Default {role} account initialized')

    conn.commit()
    conn.close()


def log_security_event(event_type, username, ip_address, details):
    """Record security audit log entry into database."""
    try:
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO security_logs (event_type, username, ip_address, details) VALUES (?, ?, ?, ?)",
            (event_type, username or 'Anonymous', ip_address, details)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error logging security event: {e}")


# ==========================================
# INPUT VALIDATION
# ==========================================
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
USERNAME_REGEX = re.compile(r'^[a-zA-Z0-9_]{3,25}$')

def validate_registration_input(username, email, password):
    """
    Validates user registration input against security constraints.
    Returns: (is_valid: bool, error_messages: list)
    """
    errors = []

    # Username validation
    if not username or not USERNAME_REGEX.match(username):
        errors.append("Username must be between 3 and 25 alphanumeric characters (underscores allowed).")

    # Email validation
    if not email or not EMAIL_REGEX.match(email):
        errors.append("Please provide a valid email address.")

    # Password policy validation
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long.")
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter (A-Z).")
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter (a-z).")
    if not re.search(r'[0-9]', password):
        errors.append("Password must contain at least one numerical digit (0-9).")
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append("Password must contain at least one special character (!@#$%^&* etc.).")

    return (len(errors) == 0, errors)


# ==========================================
# AUTHENTICATION & AUTHORIZATION DECORATORS
# ==========================================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Authentication required. Please log in to access this resource.", "warning")
            return redirect(url_for('login', next=request.path))
        return f(*args, **kwargs)
    return decorated_function


def role_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash("Authentication required.", "warning")
                return redirect(url_for('login', next=request.path))

            user_role = session.get('role', 'user')
            if user_role not in allowed_roles:
                client_ip = request.remote_addr or '127.0.0.1'
                username = session.get('username', 'Unknown')
                log_security_event(
                    'UNAUTHORIZED_ACCESS_ATTEMPT',
                    username,
                    client_ip,
                    f"Blocked access to '{request.path}'. Required roles: {allowed_roles}, User role: '{user_role}'"
                )
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# ==========================================
# SECURITY HEADERS
# ==========================================
@app.after_request
def apply_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response


# ==========================================
# APPLICATION ROUTES
# ==========================================
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        client_ip = request.remote_addr or '127.0.0.1'

        # Confirmation check
        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template('register.html', username=username, email=email)

        # Input validation
        is_valid, validation_errors = validate_registration_input(username, email, password)
        if not is_valid:
            for error in validation_errors:
                flash(error, "danger")
            return render_template('register.html', username=username, email=email)

        conn = get_db_connection()
        cursor = conn.cursor()

        # Duplicate account prevention
        cursor.execute("SELECT username, email FROM users WHERE username = ? OR email = ?", (username, email))
        existing_user = cursor.fetchone()
        if existing_user:
            conn.close()
            if existing_user['username'] == username:
                flash("Username is already taken. Please choose another.", "danger")
            else:
                flash("An account with this email address already exists.", "danger")
            return render_template('register.html', username=username, email=email)

        # Hash password securely using bcrypt with automatic salt generation
        salt = bcrypt.gensalt(rounds=12)
        password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

        cursor.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'user')",
            (username, email, password_hash)
        )
        conn.commit()
        conn.close()

        log_security_event('USER_REGISTERED', username, client_ip, 'New user successfully registered')
        flash("Registration successful! You can now log in with your credentials.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        identifier = request.form.get('identifier', '').strip()
        password = request.form.get('password', '')
        client_ip = request.remote_addr or '127.0.0.1'

        if not identifier or not password:
            flash("Please provide both username/email and password.", "danger")
            return render_template('login.html', identifier=identifier)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            (identifier, identifier.lower())
        )
        user = cursor.fetchone()
        conn.close()

        # Constant-time comparison via bcrypt checkpw to prevent timing attacks
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            # Regenerate / Establish Session
            session.clear()
            session.permanent = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['email'] = user['email']
            session['role'] = user['role']
            session['login_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            log_security_event('LOGIN_SUCCESS', user['username'], client_ip, f"User logged in with role: {user['role']}")
            flash(f"Welcome back, {user['username']}! Logged in as [{user['role'].upper()}].", "success")

            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):
                return redirect(next_page)
            return redirect(url_for('dashboard'))
        else:
            log_security_event('LOGIN_FAILED', identifier, client_ip, 'Failed authentication attempt')
            flash("Invalid credentials. Please verify your username and password.", "danger")
            return render_template('login.html', identifier=identifier)

    return render_template('login.html')


@app.route('/logout', methods=['POST'])
def logout():
    username = session.get('username', 'Unknown')
    client_ip = request.remote_addr or '127.0.0.1'
    log_security_event('LOGOUT', username, client_ip, 'User session terminated')
    session.clear()
    flash("You have been safely logged out. Session destroyed.", "info")
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, role, created_at FROM users WHERE id = ?", (session['user_id'],))
    user_data = cursor.fetchone()

    # Retrieve recent security events associated with this user
    cursor.execute(
        "SELECT timestamp, event_type, details, ip_address FROM security_logs WHERE username = ? ORDER BY id DESC LIMIT 5",
        (session['username'],)
    )
    user_logs = cursor.fetchall()
    conn.close()

    return render_template('dashboard.html', user=user_data, logs=user_logs)


@app.route('/admin')
@role_required(['admin'])
def admin():
    conn = get_db_connection()
    cursor = conn.cursor()

    # User management list
    cursor.execute("SELECT id, username, email, role, created_at FROM users ORDER BY id ASC")
    all_users = cursor.fetchall()

    # Security audit logs
    cursor.execute("SELECT id, timestamp, event_type, username, ip_address, details FROM security_logs ORDER BY id DESC LIMIT 20")
    security_logs = cursor.fetchall()

    # Summary statistics
    cursor.execute("SELECT COUNT(*) as total_users FROM users")
    total_users = cursor.fetchone()['total_users']

    cursor.execute("SELECT COUNT(*) as admin_count FROM users WHERE role = 'admin'")
    admin_count = cursor.fetchone()['admin_count']

    cursor.execute("SELECT COUNT(*) as incident_count FROM security_logs WHERE event_type = 'UNAUTHORIZED_ACCESS_ATTEMPT'")
    incident_count = cursor.fetchone()['incident_count']

    conn.close()

    return render_template(
        'admin.html',
        users=all_users,
        logs=security_logs,
        total_users=total_users,
        admin_count=admin_count,
        incident_count=incident_count
    )


@app.route('/admin/toggle_role/<int:user_id>', methods=['POST'])
@role_required(['admin'])
def toggle_role(user_id):
    if user_id == session['user_id']:
        flash("You cannot alter your own administrative role.", "warning")
        return redirect(url_for('admin'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username, role FROM users WHERE id = ?", (user_id,))
    target_user = cursor.fetchone()

    if target_user:
        new_role = 'admin' if target_user['role'] == 'user' else 'user'
        cursor.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
        conn.commit()

        client_ip = request.remote_addr or '127.0.0.1'
        log_security_event(
            'ROLE_UPDATED',
            session['username'],
            client_ip,
            f"Changed role for user '{target_user['username']}' from '{target_user['role']}' to '{new_role}'"
        )
        flash(f"User '{target_user['username']}' role changed to [{new_role.upper()}].", "success")
    else:
        flash("User not found.", "danger")

    conn.close()
    return redirect(url_for('admin'))


# ==========================================
# ERROR HANDLERS
# ==========================================
@app.errorhandler(403)
def forbidden_error(e):
    return render_template('errors/403.html'), 403


@app.errorhandler(404)
def not_found_error(e):
    return render_template('errors/404.html'), 404


@app.errorhandler(500)
def internal_error(e):
    return render_template('errors/500.html'), 500


if __name__ == '__main__':
    init_db()
    print("==================================================")
    print("Application Security Prototype Server Running!")
    print("Demo Admin Account:   admin   / Admin@12345!")
    print("Demo User Account:    johndoe / User@12345!")
    print("Local URL: http://127.0.0.1:5000")
    print("==================================================")
    app.run(host='127.0.0.1', port=5000, debug=True)
