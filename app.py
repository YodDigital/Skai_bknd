import os
from pathlib import Path
from dotenv import load_dotenv
import sqlite3
from flask import Flask, request
from werkzeug.utils import secure_filename
from datetime import datetime
import requests
from werkzeug.datastructures import FileStorage
from dwh_agents.dwh_code_generator_agent import create_dwh_agent
from dwh_agents.dwh_code_executor_agent import create_executor_agent
import pandas as pd

from sql_queries import SQL_QUERIES

load_dotenv(override=True)


app = Flask(__name__)

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

# LLM config for DWH agents
llm_config = {
    "model": "gpt-4o-mini", 
    "api_key": os.environ.get("OPENAI_API_KEY")
}

ALLOWED_EXTENSIONS = {'csv'}

# 🔁 CHANGED: Use sqlite3 instead of psycopg2
def get_connection():
    db_path = os.getenv('DATABASE_URL', 'app.db')
    
    # Make sure the directory exists
    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.exists(db_dir):
        print(f"Creating directory for database: {db_dir}")
        os.makedirs(db_dir)
        
    return sqlite3.connect(db_path)

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
    """Generate data warehouse using DWH agents."""
    # Set up working directory for this user
    user_work_dir = WORK_DIR / f"user_{user_id}"
    os.makedirs(user_work_dir, exist_ok=True)
    
    # Copy the uploaded CSV to the user's work directory
    user_csv_path = user_work_dir / os.path.basename(csv_path)
    os.system(f"cp {csv_path} {user_csv_path}")
    
    # Create database path for this user
    db_path = user_work_dir / "database.db"
    schema_path = user_work_dir / "schema_description.txt"
    generated_code_path = user_work_dir / "generated_dwh.py"
    
    # Create agents
    generator = create_dwh_agent(llm_config)
    executor = create_executor_agent(user_work_dir)
    
    try:
        # Read column names from CSV
        df = pd.read_csv(user_csv_path, nrows=1)
        column_names = df.columns.tolist()
        
        # Create the message for DWH generation
        initial_message = f"""
        Analyze the column names extracted from a CSV file and generate a star or snowflake schema-based data warehouse.
        
        Your steps:
        1. Design a schema based on the column names {column_names}.
        2. Write Python code to:
           - Load the CSV from `{user_csv_path}`
           - Transform the data to fit your schema
           - Load the data into a relational DB (SQLite) stored in `{db_path}`
           - Enable OLAP operations (slicing, dicing, roll-up, drill-down)
           - Save the generated code to `{generated_code_path}`
        3. Create a `schema_description.txt` in `{user_work_dir}` including:
           - Table and column names
           - Column roles (dimension/measure)
           - Data types
           - Every unique values per column
        4. Share the code with the execution agent.
        5. If any execution errors are returned, fix the code and resend it until it executes successfully.
        """
        
        # Start the conversation between agents
        generator.initiate_chat(
            executor,
            message=initial_message,
            request_reply=False,
            max_turns=15,
        )
        
        # Return paths to the generated files
        return str(schema_path), str(db_path)
    
    except Exception as e:
        print(f"Error in DWH generation: {e}")
        return None, None
    
@app.route('/')
def home():
    return """
    <html>
        <body>
            <h1>DWH System</h1>
            <form action="/api/user" method="post" enctype="multipart/form-data">
                <div>
                    <label>Username:</label>
                    <input type="text" name="username" required>
                </div>
                <div>
                    <label>Password:</label>
                    <input type="password" name="password" required>
                </div>
                <div>
                    <label>CSV File:</label>
                    <input type="file" name="data_file" required>
                </div>
                <button type="submit">Submit</button>
            </form>
        </body>
    </html>
    """


@app.post('/api/user')
def create_user():
    username = request.form.get('username')
    password = request.form.get('password')
    uploaded_file = request.files.get('data_file')

    if not username or not password or not uploaded_file:
        return {"error": "Missing fields"}, 400

    if not allowed_file(uploaded_file.filename):
        return {"error": "Only CSV files allowed"}, 400

    filename = secure_filename(f"{username}_{datetime.now().strftime('%Y%m%d%H%M%S')}.csv")
    local_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    uploaded_file.save(local_path)

    file_path = upload_to_escuelajs(local_path)

    conn = get_connection()
    conn.row_factory = sqlite3.Row  # Optional: makes result dict-like
    try:
        cursor = conn.cursor()

        # Create tables if they don't exist
        cursor.execute(SQL_QUERIES['create_user_table'])
        cursor.execute(SQL_QUERIES['create_db_table'])
        cursor.execute(SQL_QUERIES['create_dwh_table'])

        # Insert user
        cursor.execute(SQL_QUERIES['insert_user_return_id'], (username, password))
        user_id = cursor.lastrowid

        # Insert file reference
        cursor.execute(SQL_QUERIES['insert_user_data_id'], 
                       (user_id, 'file', file_path, None, None))
        user_data_source_id = cursor.lastrowid
        
        conn.commit()

        # Generate DWH for this user
        schema_path, db_path = generate_dwh_for_user(user_id, local_path)
        db_file_path = upload_to_escuelajs(db_path)
        schema_file_path = upload_to_escuelajs(schema_path)
        
        # Update the user_data with DWH paths
        if schema_path and db_path:
            cursor.execute(SQL_QUERIES['insert_user_warehouse_id'], 
                          (user_id, user_data_source_id, db_file_path, schema_file_path))
            conn.commit()
            return {
                "message": "User created and DWH generated successfully", 
                "user_id": user_id,
                "username": username,
                "dwh_schema": schema_file_path,
                "dwh_database": db_file_path
            }, 201
        else:
            return {
                "message": "User created but DWH generation failed",
                "user_id": user_id
            }, 201
            
    except Exception as e:
        conn.rollback()
        return {"error": str(e)}, 500
    finally:
        conn.close()


@app.post('/api/login')
def login():
    data = request.get_json()
    username, password = data.get('username'), data.get('password')

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(SQL_QUERIES['check_user_credentials'], (username, password))
        result = cursor.fetchone()
        if result:
            return {"message": "Login successful", "user_id": result[0]}, 200
        else:
            return {"error": "Invalid credentials"}, 401
    finally:
        conn.close()

@app.post('/api/data-source')
def add_data_source():
    data = request.get_json()
    user_id = data.get('user_id')
    data_type = data.get('data_type')
    file_path = data.get('file_path')
    db_link = data.get('db_link')
    access_code = data.get('access_code')

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(SQL_QUERIES['create_db_table'])
        cursor.execute(SQL_QUERIES['insert_user_data_id'], (user_id, data_type, file_path, db_link, access_code))
        data_source_id = cursor.lastrowid
        conn.commit()
        return {"message": "Data source added", "data_source_id": data_source_id}, 201
    except Exception as e:
        conn.rollback()
        return {"error": str(e)}, 500
    finally:
        conn.close()

@app.post('/api/data-warehouse')
def add_to_warehouse():
    data = request.get_json()
    user_id = data.get('user_id')
    user_data_source_id = data.get('user_data_source_id')
    warehouse_file_path = data.get('warehouse_file_path')
    schema_description = data.get('schema_description')

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(SQL_QUERIES['create_dwh_table'])
        cursor.execute(SQL_QUERIES['insert_user_warehouse_id'], (user_id, user_data_source_id, warehouse_file_path, schema_description))
        warehouse_id = cursor.lastrowid
        conn.commit()
        return {"message": "Warehouse record added", "warehouse_id": warehouse_id}, 201
    except Exception as e:
        conn.rollback()
        return {"error": str(e)}, 500
    finally:
        conn.close()

@app.route('/debug/db-status')
def debug_db_status():
    db_path = os.getenv('DATABASE_URL', 'app.db')
    abs_path = os.path.abspath(db_path)
    
    status = {
        "env_var": os.getenv('DATABASE_URL'),
        "resolved_path": db_path,
        "absolute_path": abs_path,
        "current_dir": os.getcwd(),
        "file_exists": os.path.exists(abs_path),
        "directory_exists": os.path.exists(os.path.dirname(abs_path) or os.getcwd()),
        "is_directory": os.path.isdir(abs_path) if os.path.exists(abs_path) else False,
        "file_size_bytes": os.path.getsize(abs_path) if os.path.exists(abs_path) and not os.path.isdir(abs_path) else None,
        "parent_directory_writable": os.access(os.path.dirname(abs_path) or os.getcwd(), os.W_OK)
    }
    
    # Try connecting
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT sqlite_version();")
        version = cursor.fetchone()
        status["connection_successful"] = True
        status["sqlite_version"] = version[0] if version else "Unknown"
        conn.close()
    except Exception as e:
        status["connection_successful"] = False
        status["connection_error"] = str(e)
    
    return status


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)