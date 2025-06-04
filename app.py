import os
import secrets
import re
import sqlite3
import requests
import pandas as pd
from datetime import datetime, timedelta
from pathlib import Path
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import Flask, request, jsonify, session, redirect, url_for, render_template, flash, make_response, current_app
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from urllib.parse import quote, urlencode

from dwh_agents.dwh_code_generator_agent import create_dwh_agent
from dwh_agents.dwh_code_executor_agent import create_executor_agent

from sql_queries import SQL_QUERIES

load_dotenv(override=True)


app = Flask(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)  # Generate a secure random key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # Session expires after 1 hour

# Configure upload and workspace directories - both relative to current working directory
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')
app.config['WORKSPACE_FOLDER'] = os.path.join(os.getcwd(), 'workspace')

# Create directories if they don't exist
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])
if not os.path.exists(app.config['WORKSPACE_FOLDER']):
    os.makedirs(app.config['WORKSPACE_FOLDER'])

# Use the workspace folder from app.config
WORK_DIR = Path(app.config['WORKSPACE_FOLDER']).absolute()

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# LLM config for DWH agents
llm_config = {
    "model": "gpt-4o-mini", 
    "api_key": os.environ.get("OPENAI_API_KEY")
}

ALLOWED_EXTENSIONS = {'csv'}

# Password validation
def is_password_strong(password):
    """Check if a password meets security requirements"""
    if len(password) < 12:
        return False
    # Check for at least one uppercase, lowercase, digit, and special character
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# User model
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    # email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    user_db = db.relationship('Database', backref='author', uselist=False, lazy=True)  # One-to-many relationship
    user_dwh = db.relationship('DataWarehouse', backref='author', uselist=False, lazy=True)  # One-to-many relationship

    def set_password(self, password):
        """Hash the password for storing in the database"""
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256:150000')

    def check_password(self, password):
        """Check if the provided password matches the hash"""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class Database(db.Model):
    __tablename__ = 'user_data_sources'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # Foreign key
    data_type = db.Column(db.String(80), nullable=False)
    file_path = db.Column(db.String(200), nullable=False)
    db_link = db.Column(db.String(80), unique=True, nullable=True)
    access_code = db.Column(db.String(80), unique=True, nullable=True)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_dwh = db.relationship('DataWarehouse', backref='db_source', uselist=False, lazy=True)  # One-to-many relationship

    # def __repr__(self):
    #     return f'<Database {self.data_type}>'

class DataWarehouse(db.Model):
    __tablename__ = 'user_data_warehouse'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # Foreign key
    user_data_source_id = db.Column(db.Integer, db.ForeignKey('user_data_sources.id'), nullable=False)  # Foreign key
    warehouse_file_path = db.Column(db.String(200), nullable=False)
    schema_description = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Create database tables
with app.app_context():
    # db_path = os.path.join(current_app.instance_path, 'app.db')
    # if os.path.exists(db_path):
    #     os.remove(db_path)  # Delete the existing database file

    db.create_all()
    # Create DWH related tables using raw SQL
    conn = sqlite3.connect('instance/app.db')
    cursor = conn.cursor()
    cursor.execute(SQL_QUERIES['create_user_table'])
    cursor.execute(SQL_QUERIES['create_db_table'])
    cursor.execute(SQL_QUERIES['create_dwh_table'])
    conn.commit()
    conn.close()
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def upload_to_escuelajs(filepath):
    with open(filepath, 'rb') as f:
        response = requests.post("https://api.escuelajs.co/api/v1/files/upload", files={'file': f})
    try:
        response.raise_for_status()
        return response.json().get('location')
    except requests.exceptions.RequestException as e:
        print(f"Error uploading file: {e}")
        print("Response:", response.text)
        return None


def generate_dwh_for_user(user_id, csv_path):
    """Enhanced version using pandas-profiling for automatic data analysis."""
    
    user_work_dir = Path(f"user_{user_id}")
    user_work_dir.mkdir(exist_ok=True)
    
    user_csv_path = user_work_dir / os.path.basename(csv_path)
    os.system(f"cp {csv_path} {user_csv_path}")
    
    db_path = user_work_dir / "database.db"
    schema_path = user_work_dir / "schema_description.json"
    
    generator = create_dwh_agent(llm_config)
    executor = create_executor_agent(user_work_dir)
    
    try:
        # Enhanced message with profiling
        initial_message = f"""
Create a data warehouse using automatic data profiling:

```python
import pandas as pd
import sqlite3
import json
from ydata_profiling import ProfileReport  # pip install ydata-profiling

# Load and profile the data
df = pd.read_csv('{csv_path}')
profile = ProfileReport(df, title="Data Analysis", explorative=True)

# Extract insights from profile
dataset_info = profile.get_description()

# Use profile insights to automatically:
# 1. Identify categorical vs numeric columns
# 2. Detect potential keys (high cardinality, unique values)
# 3. Find relationships between columns
# 4. Determine appropriate data types

# Create star schema based on actual data patterns
# No guessing - use the profiling results

# Build database with proper schema
conn = sqlite3.connect('{db_path}')
conn.execute("PRAGMA foreign_keys = ON")

# Implementation here...
```

Use the profiling results to make intelligent schema decisions.
Save schema description to {schema_path} as JSON.
        """
        
        generator.initiate_chat(
            executor,
            message=initial_message,
            max_turns=10,
        )
        
        # if db_path.exists() and schema_path.exists():
        return str(schema_path), str(db_path)
        # else:
        #     return None, None
    
    except Exception as e:
        print(f"Error: {e}")
        return None, None
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        # email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        data_file = request.files.get('data_file')
        
        # Form validation
        error = None
        # if not username or not email or not password or not data_file:
        if not username or not password or not data_file:
            error = 'All fields are required'
        elif password != confirm_password:
            error = 'Passwords do not match'
        elif not is_password_strong(password):
            error = 'Password must be at least 12 characters and include uppercase, lowercase, numbers, and special characters'
        elif User.query.filter_by(username=username).first():
            error = 'Username already exists'
        # elif User.query.filter_by(email=email).first():
        #     error = 'Email already registered'
        
            
        if error:
            flash(error, 'error')
            return render_template('register.html')
        
        try:
            # Create new user with secure password
            # new_user = User(username=username, email=email)
            new_user = User(username=username)
            new_user.set_password(password)

            
            filename = secure_filename(f"{username}_{datetime.now().strftime('%Y%m%d%H%M%S')}.csv")
            local_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            data_file.save(local_path)

            file_path = upload_to_escuelajs(local_path)

            new_db_file =  Database(data_type='file', file_path=file_path, db_link=None, access_code=None)
            new_user.user_db = new_db_file

            #Generate DWH for this user
            schema_path, db_path = generate_dwh_for_user(new_user.id, local_path)
            db_file_path = upload_to_escuelajs(db_path)
            schema_file_path = upload_to_escuelajs(schema_path)
            
            # Update the user_data with DWH paths
            if not all([schema_path, db_path]):
                raise ValueError("Failed to generate DWH files")
            
            new_dwh_file = DataWarehouse(warehouse_file_path=db_file_path, schema_description=schema_file_path)
            new_user.user_dwh = new_dwh_file
            new_db_file.user_dwh = new_dwh_file
            db.session.add(new_user)
            db.session.commit()

            # return User.query.all() 
            
            # Clean up local files
            if os.path.exists(local_path):
                os.remove(local_path)
            if os.path.exists(db_path):
                os.remove(db_path)
            if os.path.exists(schema_path):
                os.remove(schema_path)

            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        
        except Exception as e:
            db.session.rollback()
            flash(f'Registration failed: {str(e)}', 'error')
            # Clean up any partial files
            if 'local_path' in locals() and os.path.exists(local_path):
                os.remove(local_path)
            return render_template('register.html')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        # Check for account lockout
        if user and user.locked_until and user.locked_until > datetime.utcnow():
            remaining_time = user.locked_until - datetime.utcnow()
            minutes = remaining_time.total_seconds() // 60
            flash(f'Account is temporarily locked. Try again in {int(minutes)} minutes.', 'error')
            return render_template('login.html')
        
        # Validate credentials
        if not user or not user.check_password(password):
            if user:
                # Increment failed login attempts
                user.failed_login_attempts += 1
                
                # Lock account after 5 failed attempts
                if user.failed_login_attempts >= 5:
                    user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                    flash('Too many failed login attempts. Account locked for 15 minutes.', 'error')
                else:
                    flash('Invalid username or password', 'error')
                    
                db.session.commit()
            else:
                flash('Invalid username or password', 'error')
                
            return render_template('login.html')
        
        # Reset failed login attempts on successful login
        user.failed_login_attempts = 0
        user.locked_until = None
        db.session.commit()
        
        # Set up user session
        session.clear()
        session['user_id'] = user.id
        session['username'] = user.username
        session['dwh_file'] = {
            'warehouse_file_path': user.user_dwh.warehouse_file_path,
            'schema_description': user.user_dwh.schema_description
            # Add other needed fields
        }
        session.permanent = True

        global glo_dwh, glo_schema_file, glo_id, glo_name
        glo_id = user.id
        glo_name = user.username
        glo_dwh = user.user_dwh.warehouse_file_path
        glo_schema_file = user.user_dwh.schema_description
        
        # flash(f'Welcome back, {user.username}!', 'success')
        return redirect(url_for('start_chat'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

# @app.route('/chat')
# @login_required
# def launch_chat():
#     if 'user_id' not in session:
#         return redirect(url_for('login'))
#     return redirect(f"http://0.0.0.0:4200?user_id={session['user_id']}")


@app.route('/api/user_session/<user_id>')
# @login_required
def get_user_session(user_id):
    if glo_id != int(user_id):
        return jsonify({"error": "Unauthorized"}), 403
    
    # Add more comprehensive session data
    response_data = {
        "warehouse_file_path": glo_dwh,
        "schema_description": glo_schema_file, 
        "username": glo_name,
        "user_id": glo_id
    }
    
    # Add CORS headers for cross-origin requests from Chainlit
    response = jsonify(response_data)
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE')
    
    return response

@app.route('/start-chat')
@login_required
def start_chat():
    """Endpoint that redirects to Chainlit with auth parameters stored in cookies"""
    
    # Validate that user has uploaded a database file
    if 'dwh_file' not in session or not session['dwh_file'].get('warehouse_file_path') or not session['dwh_file'].get('schema_description'):
        flash('Please upload a database file before starting chat.', 'error')
        return redirect(url_for('register'))  # Redirect to upload page
    
    # Create a simple token (or use JWT for better security)
    auth_token = f"{session['user_id']}-{secrets.token_urlsafe(16)}"
    
    # Get the current Flask base URL
    flask_base_url = request.url_root
    
    # Get Chainlit URL
    chainlit_base_url = os.environ.get('CHAINLIT_URL', 'https://chainlitsaascorrect-production.up.railway.app')
    
    # Create response object for redirect
    response = make_response(redirect(chainlit_base_url))
    
    # Set cookies with auth parameters
    # These cookies will be accessible to Chainlit since it's on the same domain or you can set domain
    cookie_options = {
        'max_age': 3600,  # 1 hour expiry
        'secure': True,   # Only send over HTTPS
        'httponly': False,  # Allow JavaScript access (needed for Chainlit to read them)
        'samesite': 'None',  # Protect against CSRF while allowing cross-site navigation
        'domain': '.railway.app'
    }
    
    response.set_cookie('auth_user_id', str(session['user_id']), **cookie_options)
    response.set_cookie('auth_token', auth_token, **cookie_options)
    response.set_cookie('flask_base_url', flask_base_url, **cookie_options)
    response.set_cookie('username', session['username'], **cookie_options)
    
    # Optional: Set a timestamp for when the auth was created
    response.set_cookie('auth_timestamp', str(int(datetime.now().timestamp())), **cookie_options)
    
    return response

@app.route('/dashboard')
@login_required
def dashboard():
    # Get user's data warehouses
    conn = sqlite3.connect('instance/app.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT uw.id, uds.file_path, uw.warehouse_file_path, uw.schema_description, uw.created_at
        FROM user_data_warehouse uw
        JOIN user_data_sources uds ON uw.user_data_source_id = uds.id
        WHERE uw.user_id = ?
    ''', (session['user_id'],))
    
    warehouses = cursor.fetchall()
    conn.close()
    
    return render_template('dashboard.html', username=session.get('username'), warehouses=warehouses)

@app.route('/upload-csv', methods=['GET', 'POST'])
@login_required
def upload_csv():
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'data_file' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)
            
        uploaded_file = request.files.get('data_file')
        
        if not uploaded_file or uploaded_file.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)
            
        if not allowed_file(uploaded_file.filename):
            flash('Only CSV files allowed', 'error')
            return redirect(request.url)
            
        # Save the file with a secure filename
        filename = secure_filename(f"{session['username']}_{datetime.now().strftime('%Y%m%d%H%M%S')}.csv")
        local_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        uploaded_file.save(local_path)
        
        # Upload to external storage
        file_path = upload_to_escuelajs(local_path)
        
        # Connect to the database
        conn = sqlite3.connect('instance/users.db')
        cursor = conn.cursor()
        
        try:
            # Insert file reference
            cursor.execute(SQL_QUERIES['insert_user_data_id'], 
                          (session['user_id'], 'file', file_path, None, None))
            user_data_source_id = cursor.lastrowid
            conn.commit()
            
            # Generate DWH for this user
            schema_path, db_path = generate_dwh_for_user(session['user_id'], local_path)
            
            if schema_path and db_path:
                # Upload generated files to external storage
                db_file_path = upload_to_escuelajs(db_path)
                schema_file_path = upload_to_escuelajs(schema_path)
                
                # Update the user_data with DWH paths
                cursor.execute(SQL_QUERIES['insert_user_warehouse_id'], 
                              (session['user_id'], user_data_source_id, db_file_path, schema_file_path))
                conn.commit()
                
                flash('CSV uploaded and data warehouse generated successfully!', 'success')
            else:
                flash('CSV uploaded but data warehouse generation failed', 'warning')
                
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            conn.rollback()
            flash(f'Error: {str(e)}', 'error')
            return redirect(url_for('upload_csv'))
        finally:
            conn.close()
    
    return render_template('upload_csv.html')

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        user = User.query.get(session['user_id'])
        
        # Validate input
        if not user.check_password(current_password):
            flash('Current password is incorrect', 'error')
        elif new_password != confirm_password:
            flash('New passwords do not match', 'error')
        elif not is_password_strong(new_password):
            flash('Password must be at least 12 characters and include uppercase, lowercase, numbers, and special characters', 'error')
        else:
            # Update password
            user.set_password(new_password)
            db.session.commit()
            flash('Password updated successfully', 'success')
            return redirect(url_for('dashboard'))
            
    return render_template('change_password.html')

@app.route('/reset-password-request', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        # Always show this message even if email doesn't exist (prevents email enumeration)
        flash('If an account with that email exists, password reset instructions have been sent.', 'info')
        
        if user:
            # In a real application, you would:
            # 1. Generate a secure token
            # 2. Store it in the database with an expiration
            # 3. Send an email with a reset link
            pass
            
        return redirect(url_for('login'))
        
    return render_template('reset_password_request.html')

@app.route('/view-schema/<int:warehouse_id>')
@login_required
def view_schema(warehouse_id):
    # Get schema details for the warehouse
    conn = sqlite3.connect('instance/users.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT schema_description
        FROM user_data_warehouse
        WHERE id = ? AND user_id = ?
    ''', (warehouse_id, session['user_id']))
    
    warehouse = cursor.fetchone()
    conn.close()
    
    if not warehouse:
        flash('Warehouse not found or access denied', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('view_schema.html', schema=warehouse['schema_description'])


# @app.post('/api/user')
# def create_user():
#     username = request.form.get('username')
#     password = request.form.get('password')
#     uploaded_file = request.files.get('data_file')

#     if not username or not password or not uploaded_file:
#         return {"error": "Missing fields"}, 400

#     if not allowed_file(uploaded_file.filename):
#         return {"error": "Only CSV files allowed"}, 400

#     filename = secure_filename(f"{username}_{datetime.now().strftime('%Y%m%d%H%M%S')}.csv")
#     local_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
#     uploaded_file.save(local_path)

#     file_path = upload_to_escuelajs(local_path)

#     conn = get_connection()
#     conn.row_factory = sqlite3.Row  # Optional: makes result dict-like
#     try:
#         cursor = conn.cursor()

#         # Create tables if they don't exist
#         cursor.execute(SQL_QUERIES['create_user_table'])
#         cursor.execute(SQL_QUERIES['create_db_table'])
#         cursor.execute(SQL_QUERIES['create_dwh_table'])

#         # Insert user
#         cursor.execute(SQL_QUERIES['insert_user_return_id'], (username, password))
#         user_id = cursor.lastrowid

#         # Insert file reference
#         cursor.execute(SQL_QUERIES['insert_user_data_id'], 
#                        (user_id, 'file', file_path, None, None))
#         user_data_source_id = cursor.lastrowid
        
#         conn.commit()

#         # Generate DWH for this user
#         schema_path, db_path = generate_dwh_for_user(user_id, local_path)
#         db_file_path = upload_to_escuelajs(db_path)
#         schema_file_path = upload_to_escuelajs(schema_path)
        
#         # Update the user_data with DWH paths
#         if schema_path and db_path:
#             cursor.execute(SQL_QUERIES['insert_user_warehouse_id'], 
#                           (user_id, user_data_source_id, db_file_path, schema_file_path))
#             conn.commit()
#             return {
#                 "message": "User created and DWH generated successfully", 
#                 "user_id": user_id,
#                 "username": username,
#                 "dwh_schema": schema_file_path,
#                 "dwh_database": db_file_path
#             }, 201
#         else:
#             return {
#                 "message": "User created but DWH generation failed",
#                 "user_id": user_id
#             }, 201
            
#     except Exception as e:
#         conn.rollback()
#         return {"error": str(e)}, 500
#     finally:
#         conn.close()

# @app.post('/api/data-source')
# def add_data_source():
#     data = request.get_json()
#     user_id = data.get('user_id')
#     data_type = data.get('data_type')
#     file_path = data.get('file_path')
#     db_link = data.get('db_link')
#     access_code = data.get('access_code')

#     conn = get_connection()
#     try:
#         cursor = conn.cursor()
#         cursor.execute(SQL_QUERIES['create_db_table'])
#         cursor.execute(SQL_QUERIES['insert_user_data_id'], (user_id, data_type, file_path, db_link, access_code))
#         data_source_id = cursor.lastrowid
#         conn.commit()
#         return {"message": "Data source added", "data_source_id": data_source_id}, 201
#     except Exception as e:
#         conn.rollback()
#         return {"error": str(e)}, 500
#     finally:
#         conn.close()

# @app.post('/api/data-warehouse')
# def add_to_warehouse():
#     data = request.get_json()
#     user_id = data.get('user_id')
#     user_data_source_id = data.get('user_data_source_id')
#     warehouse_file_path = data.get('warehouse_file_path')
#     schema_description = data.get('schema_description')

#     conn = get_connection()
#     try:
#         cursor = conn.cursor()
#         cursor.execute(SQL_QUERIES['create_dwh_table'])
#         cursor.execute(SQL_QUERIES['insert_user_warehouse_id'], (user_id, user_data_source_id, warehouse_file_path, schema_description))
#         warehouse_id = cursor.lastrowid
#         conn.commit()
#         return {"message": "Warehouse record added", "warehouse_id": warehouse_id}, 201
#     except Exception as e:
#         conn.rollback()
#         return {"error": str(e)}, 500
#     finally:
#         conn.close()


# @app.post('/api/login')
# def login():
#     data = request.get_json()
#     username, password = data.get('username'), data.get('password')

#     conn = get_connection()
#     try:
#         cursor = conn.cursor()
#         cursor.execute(SQL_QUERIES['check_user_credentials'], (username, password))
#         result = cursor.fetchone()
#         if result:
#             return {"message": "Login successful", "user_id": result[0]}, 200
#         else:
#             return {"error": "Invalid credentials"}, 401
#     finally:
#         conn.close()


# @app.route('/debug/db-status')
# def debug_db_status():
#     db_path = os.getenv('DATABASE_URL', 'app.db')
#     abs_path = os.path.abspath(db_path)
    
#     status = {
#         "env_var": os.getenv('DATABASE_URL'),
#         "resolved_path": db_path,
#         "absolute_path": abs_path,
#         "current_dir": os.getcwd(),
#         "file_exists": os.path.exists(abs_path),
#         "directory_exists": os.path.exists(os.path.dirname(abs_path) or os.getcwd()),
#         "is_directory": os.path.isdir(abs_path) if os.path.exists(abs_path) else False,
#         "file_size_bytes": os.path.getsize(abs_path) if os.path.exists(abs_path) and not os.path.isdir(abs_path) else None,
#         "parent_directory_writable": os.access(os.path.dirname(abs_path) or os.getcwd(), os.W_OK)
#     }
    
#     # Try connecting
#     try:
#         conn = get_connection()
#         cursor = conn.cursor()
#         cursor.execute("SELECT sqlite_version();")
#         version = cursor.fetchone()
#         status["connection_successful"] = True
#         status["sqlite_version"] = version[0] if version else "Unknown"
#         conn.close()
#     except Exception as e:
#         status["connection_successful"] = False
#         status["connection_error"] = str(e)
    
#     return status


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)


#raph.Lambou@gmail.com8