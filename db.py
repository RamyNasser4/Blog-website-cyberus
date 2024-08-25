import sqlite3

def get_db_connection():
    conn = sqlite3.connect('project.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_users():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            assets INTEGER NOT NULL DEFAULT 0,
            user_type INTEGER NOT NULL DEFAULT 0
        )
    ''')
    conn.close()
def get_users():
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.close()
    return users


def get_user_by_username(username):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    return user

def get_user_by_id(id):
    conn = get_db_connection()
    # Fetch the user details based on the ID passed in the URL
    user = conn.execute('SELECT * FROM users WHERE id = ?', (id,)).fetchone()
    conn.close()
    return user

def update_user_without_password(username,assets,user_type,id):
    conn = get_db_connection()
    conn.execute('UPDATE users SET username = ?, assets = ?, user_type = ? WHERE id = ?',
                         (username, assets, user_type, id))
    conn.commit()
    conn.close()
    
def update_user_with_password(username,hashed_password,assets,user_type,id):
    conn = get_db_connection()
    conn.execute('UPDATE users SET username = ?, password = ?, assets = ?, user_type = ? WHERE id = ?',
                         (username, hashed_password, assets, user_type, id))
    conn.commit()
    conn.close()

def add_user(username,hashed_password,assets):
    conn = get_db_connection()
    conn.execute('INSERT INTO users (username, password, assets) VALUES (?, ?, ?)',
                     (username, hashed_password, assets))
    conn.commit()
    conn.close()
def add_admin(username,hashed_password):
    conn = get_db_connection()
    conn.execute('INSERT INTO users (username, password, assets, user_type) VALUES (?, ?, ?, ?)',
                         (username, hashed_password, 0, 2))
    conn.commit()
    conn.close()


def delete_user(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM users WHERE id = ?', (id,))
    conn.commit()
    conn.close()

def check_if_admin_exists():
    conn = get_db_connection()
    admin_exists = conn.execute('SELECT 1 FROM users WHERE user_type = 2 LIMIT 1').fetchone()
    conn.close()
    return admin_exists