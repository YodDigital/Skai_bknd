SQL_QUERIES = {
    "create_user_table": """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            username TEXT NOT NULL, 
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            failed_login_attempts INTEGER DEFAULT 0,
            locked_until TIMESTAMP
        );
    """,

    "create_db_table": """
        CREATE TABLE IF NOT EXISTS user_data_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            data_type TEXT NOT NULL,
            file_path TEXT,
            db_link TEXT,
            access_code TEXT,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    """,

    "create_dwh_table": """
        CREATE TABLE IF NOT EXISTS user_data_warehouse (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            user_data_source_id INTEGER NOT NULL,
            warehouse_file_path TEXT NOT NULL,
            schema_description TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (user_data_source_id) REFERENCES user_data_sources(id) ON DELETE CASCADE
        );
    """,

    # 🚫 SQLite doesn't support RETURNING, so remove it
    "insert_user_return_id": """
        INSERT INTO users (username, password)
        VALUES (?, ?);
    """,

    "check_user_credentials": """
        SELECT id FROM users WHERE username = ? AND password = ?;
    """,

    "insert_user_data_id": """
        INSERT INTO user_data_sources (user_id, data_type, file_path, db_link, access_code)
        VALUES (?, ?, ?, ?, ?);
    """,

    "insert_user_warehouse_id": """
        INSERT INTO user_data_warehouse (user_id, user_data_source_id, warehouse_file_path, schema_description)
        VALUES (?, ?, ?, ?);
    """
}
