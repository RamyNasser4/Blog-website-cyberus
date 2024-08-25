from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import secrets
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

def get_db_connection():
    conn = sqlite3.connect('project.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def welcome_page():
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
    return render_template('index.html')

@app.route('/user_panel')
def user_panel():
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    username = session['username']

    # Fetch user details from the database
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()

    if user is None:
        return redirect(url_for('login'))

    return render_template('user_panel.html', user=user)
@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def update_user(id):
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()

    # Fetch the user details based on the ID passed in the URL
    user = conn.execute('SELECT * FROM users WHERE id = ?', (id,)).fetchone()
    
    if user is None:
        return redirect(url_for('user_panel'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        assets = request.form.get('assets', user['assets'])  # Use the existing value if not provided
        user_type = request.form.get('user_type', user['user_type'])  # Use the existing value if not provided

        if not username:
            return "Missing form data", 400

        # Update the user's data in the database
        if password ==user['password']:  # Only hash the password if it has been changed
           conn.execute('UPDATE users SET username = ?, assets = ?, user_type = ? WHERE id = ?',
                         (username, assets, user_type, id))            

        else:  # Update without changing the password
            hashed_password = generate_password_hash(password)
            conn.execute('UPDATE users SET username = ?, password = ?, assets = ?, user_type = ? WHERE id = ?',
                         (username, hashed_password, assets, user_type, id)) 

        conn.commit()
        conn.close()
        return redirect(url_for('manage_admins'))

    conn.close()
    return render_template('update_user.html', user=user)

@app.route('/add', methods=('GET', 'POST'))
def add_user():
    conn = get_db_connection()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        assets = request.form['assets']

        hashed_password = generate_password_hash(password)
        conn.execute('INSERT INTO users (username, password, assets) VALUES (?, ?, ?)',
                     (username, hashed_password, assets))
        conn.commit()
        conn.close()
        return redirect(url_for('welcome_page'))

    return render_template('add_user.html')

@app.route('/delete/<int:id>', methods=['POST'])
def delete_user(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM users WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    return redirect(url_for('manage_admins'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    conn = get_db_connection()
    error = None

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        # Query the database to verify the user's credentials
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user is None or not check_password_hash(user['password'], password):
            error = 'Invalid credentials. Please try again.'
        else:
            session['username'] = username
            if user['user_type'] == 2:
                return redirect(url_for('manage_admins'))
            else:
                return redirect(url_for('user_panel'))

    conn.close()
    return render_template('login.html', error=error)

@app.route('/manage_admins', methods=['GET', 'POST'])
def manage_admins():
    conn = get_db_connection()

    # Check if there are any existing admins
    admin_exists = conn.execute('SELECT 1 FROM users WHERE user_type = 2 LIMIT 1').fetchone()

    # If there are no admins, allow access without authentication
    if admin_exists is None:
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']

            hashed_password = generate_password_hash(password)
            conn.execute('INSERT INTO users (username, password, assets, user_type) VALUES (?, ?, ?, ?)',
                         (username, hashed_password, 0, 2))
            conn.commit()
            conn.close()

            session['username'] = username
            return redirect(url_for('manage_admins'))

        return render_template('create_admin.html')

    if 'username' not in session:
        return redirect(url_for('login'))

    user = conn.execute('SELECT * FROM users WHERE username = ?', (session['username'],)).fetchone()

    if user is None or user['user_type'] != 2:
        return redirect(url_for('user_panel'))

    users = conn.execute('SELECT * FROM users').fetchall()

    if request.method == 'POST':
        username = request.form['username']
        password = request.form.get('password')
        assets = request.form.get('assets')
        user_type = request.form['user_type']
        user_id = request.form['user_id']

        # Fetch the existing user data before updating
        existing_user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

        # If password is provided, hash it and update
        if password:
            hashed_password = generate_password_hash(password)
            conn.execute('UPDATE users SET username = ?, password = ?, assets = ?, user_type = ? WHERE id = ?',
                         (username, hashed_password, assets, user_type, user_id))
        else:
            conn.execute('UPDATE users SET username = ?, assets = ?, user_type = ? WHERE id = ?',
                         (username, assets, user_type, user_id))
        conn.commit()
        conn.close()
        return redirect(url_for('manage_admins'))

    conn.close()
    return render_template('manage_admins.html', users=users)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('welcome_page'))

if __name__ == '__main__':
    app.run(host="127.0.0.1", port=8080, debug=True)
