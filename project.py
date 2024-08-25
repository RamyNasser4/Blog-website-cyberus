from flask import Flask, render_template, request, redirect, url_for, session
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
import db
app = Flask(__name__)
app.secret_key = secrets.token_hex(16)



@app.route('/')
def welcome_page():
    db.init_users()
    return render_template('index.html')

@app.route('/user_panel')
def user_panel():
    if 'username' not in session:
        return redirect(url_for('login'))

    
    username = session['username']

    # Fetch user details from the database
    user = db.get_user_by_username(username)
    if user is None:
        return redirect(url_for('login'))

    return render_template('user_panel.html', user=user)

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def update_user(id):
    if 'username' not in session:
        return redirect(url_for('login'))

    user = db.get_user_by_id(id)
    
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
        if password == user['password']:  # Only hash the password if it has been changed
           db.update_user_without_password(username,assets,user_type)            

        else:  # Update without changing the password
            hashed_password = generate_password_hash(password)
            db.update_user_with_password(username,hashed_password,assets,user_type,id) 
        return redirect(url_for('manage_admins'))
    return render_template('update_user.html', user=user)

@app.route('/add', methods=('GET', 'POST'))
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        assets = request.form['assets']
        hashed_password = generate_password_hash(password)
        db.add_user(username,hashed_password,assets)
        return redirect(url_for('welcome_page'))

    return render_template('add_user.html')

@app.route('/delete/<int:id>', methods=['POST'])
def delete_user(id):
    db.delete_user(id)
    return redirect(url_for('manage_admins'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        # Query the database to verify the user's credentials
        user = db.get_user_by_username(username)

        if user is None or not check_password_hash(user['password'], password):
            error = 'Invalid credentials. Please try again.'
        else:
            session['username'] = username
            if user['user_type'] == 2:
                return redirect(url_for('manage_admins'))
            else:
                return redirect(url_for('user_panel'))
    return render_template('login.html', error=error)

@app.route('/manage_admins', methods=['GET', 'POST'])
def manage_admins():

    # Check if there are any existing admins
    admin_exists = db.check_if_admin_exists()
    # If there are no admins, allow access without authentication
    if admin_exists is None:
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']

            hashed_password = generate_password_hash(password)
            db.add_admin(username,hashed_password)

            session['username'] = username
            return redirect(url_for('manage_admins'))

        return render_template('create_admin.html')

    if 'username' not in session:
        return redirect(url_for('login'))

    user = db.get_user_by_username(username)

    if user is None or user['user_type'] != 2:
        return redirect(url_for('user_panel'))

    users = db.get_users()

    if request.method == 'POST':
        username = request.form['username']
        password = request.form.get('password')
        assets = request.form.get('assets')
        user_type = request.form['user_type']
        user_id = request.form['user_id']

        # Fetch the existing user data before updating
        existing_user = db.get_user_by_id(user_id)

        # If password is provided, hash it and update
        if password:
            hashed_password = generate_password_hash(password)
            db.update_user_with_password(username,hashed_password,assets,user_type,user_id)
        else:
            db.update_user_without_password(username,assets,user_type,user_id)
        return redirect(url_for('manage_admins'))
    return render_template('manage_admins.html', users=users)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('welcome_page'))

if __name__ == '__main__':
    app.run(host="127.0.0.1", port=8080, debug=True)
