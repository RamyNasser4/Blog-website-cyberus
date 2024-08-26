from multiprocessing import connection
import sqlite3
from flask import Flask, request, redirect, url_for, flash, send_from_directory
from werkzeug.utils import secure_filename
import os
 
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB limit
app.secret_key = 'supersecretkey'  # For flashing messages

ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif'}
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
            likes INTEGER NOT NULL DEFAULT 0,
            user_type INTEGER NOT NULL DEFAULT 0,
            profile_image_url TEXT
        )
    ''')
    conn.close()


def init_posts():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            likes INTEGER DEFAULT 0,     
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            file_url TEXT,
            FOREIGN KEY (author_id) REFERENCES users(id)
        )
    ''')
    conn.close()
def init_comments():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            content TEXT NOT NULL,
            file_url TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (post_id) REFERENCES posts(id)
        )
    ''')
    conn.close()
def init_post_likes():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS post_likes (
            user_id INTEGER NOT NULL,
            post_id INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (post_id) REFERENCES posts(id),
            PRIMARY KEY (user_id, post_id)
        )
    ''')
    conn.close()    

def get_posts_by_author(author_id):
    conn = get_db_connection()
    posts = conn.execute('SELECT * FROM posts WHERE author_id = ?', (author_id,)).fetchall()
    conn.close()
    return posts

def get_post_by_id(post_id):
    conn = get_db_connection()
    post = conn.execute('SELECT * FROM posts WHERE id = ?', (post_id,)).fetchone()
    conn.close()
    return post

def add_post(author_id, title, content, file_url=None):
    conn = get_db_connection()
    conn.execute('INSERT INTO posts (author_id, title, content, file_url) VALUES (?, ?, ?, ?)',
                 (author_id, title, content, file_url))
    conn.commit()
    conn.close()

def update_post(post_id, title, content):
    conn = get_db_connection()
    conn.execute('UPDATE posts SET title = ?, content = ? WHERE id = ?',
                 (title, content, post_id))
    conn.commit()
    conn.close()

import os

def delete_comments_by_post_id(post_id):
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row  # Ensure rows are returned as dictionaries
    cursor = conn.cursor()
    
    # Fetch all comments associated with the post_id
    cursor.execute('SELECT * FROM comments WHERE post_id = ?', (post_id,))
    comments = cursor.fetchall()
    
    # Delete media files associated with comments
    for comment in comments:
        if comment['file_url']:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], comment['file_url'])
            if os.path.exists(file_path):
                os.remove(file_path)
    
    # Delete comments from the database
    cursor.execute('DELETE FROM comments WHERE post_id = ?', (post_id,))
    
    conn.commit()
    conn.close()


@app.route('/delete_post/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    db = get_db_connection()
    user = db.get_user_by_username(session['username'])
    if user is None or user['user_type'] != 1:
        return redirect(url_for('user_panel'))

    post = db.get_post_by_id(post_id)
    if post is None or post['author_id'] != user['id']:
        return redirect(url_for('author_panel'))

    # Delete comments associated with the post
    db.delete_comments_by_post_id(post_id)

    # Delete the post from the database
    db.delete_post(post_id)

    # Remove the media file if it exists
    if post['file_url']:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], post['file_url'])
        if os.path.exists(file_path):
            os.remove(file_path)

    return redirect(url_for('author_panel'))

def get_all_posts():
    conn = get_db_connection()
    posts = conn.execute('SELECT * FROM posts').fetchall()
    conn.close()
    return posts

def get_max_post():
    conn = get_db_connection()
    id = conn.execute("SELECT MAX(id) + 1 AS next_id FROM posts").fetchone()
    conn.close()
    return str(id[0])
def get_users():
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.close()
    return users

def add_comment(post_id, username, content, file_url=None):
    conn = get_db_connection()
    conn.execute('INSERT INTO comments (post_id, username, content, file_url) VALUES (?, ?, ?, ?)',
                 (post_id, username, content, file_url))
    conn.commit()
    conn.close()

def get_max_comment():
    conn = get_db_connection()
    id = conn.execute("SELECT MAX(id) + 1 AS next_id FROM comments;").fetchone()
    conn.commit()
    conn.close()
    return str(id[0])

def get_comments_by_post(post_id):
    conn = get_db_connection()
    comments = conn.execute('SELECT * FROM comments WHERE post_id = ?', (post_id,)).fetchall()
    conn.close()
    return comments




def get_user_by_username(username):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    return user

def get_user_by_id(id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (id,)).fetchone()
    conn.close()
    return user

def update_user_without_password(username, likes, user_type, id):
    conn = get_db_connection()
    conn.execute('UPDATE users SET username = ?, likes = ?, user_type = ? WHERE id = ?',
                 (username, likes, user_type, id))
    conn.commit()
    conn.close()


def update_username(username ,id):
    conn=get_db_connection()
    conn.execute('UPDATE users SET username = ?  WHERE id = ?',(username,id))
    conn.commit()
    conn.close()

    
def update_user_with_password(username, hashed_password, likes, user_type, id):
    conn = get_db_connection()
    conn.execute('UPDATE users SET username = ?, password = ?, likes = ?, user_type = ? WHERE id = ?',
                 (username, hashed_password, likes, user_type, id))
    conn.commit()
    conn.close()

def add_user(username, hashed_password, user_type, likes=0):
    conn = get_db_connection()
    conn.execute('INSERT INTO users (username, password, user_type, likes) VALUES (?, ?, ?, ?)',
                 (username, hashed_password, user_type, likes))
    conn.commit()
    conn.close()

def add_admin(username, hashed_password):
    conn = get_db_connection()
    conn.execute('INSERT INTO users (username, password, likes, user_type) VALUES (?, ?, ?, ?)',
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

def update_user_profile(user_id, profile_image_url):
    conn = get_db_connection()
    conn.execute('UPDATE users SET profile_image_url = ? WHERE id = ?', (profile_image_url, user_id))
    conn.commit()
    conn.close()

def search_posts(query):
    conn = get_db_connection()
    posts = conn.execute('SELECT * FROM posts WHERE title LIKE ? OR content LIKE ?', ('%' + query + '%', '%' + query + '%')).fetchall()
    conn.close()
    return posts
def has_user_liked_post(user_id, post_id):
    conn = get_db_connection()
    liked = conn.execute('SELECT 1 FROM post_likes WHERE user_id = ? AND post_id = ?', (user_id, post_id)).fetchone()
    conn.close()
    return liked is not None
def record_user_like(user_id, post_id):
    conn = get_db_connection()
    conn.execute('INSERT INTO post_likes (user_id, post_id) VALUES (?, ?)', (user_id, post_id))
    conn.commit()
    conn.close()
def increment_post_likes(post_id):
    conn = get_db_connection()
    conn.execute('UPDATE posts SET likes = likes + 1 WHERE id = ?', (post_id,))
    conn.commit()
    conn.close()
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'avi', 'mov'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
 


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    
    file = request.files['file']
    
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        flash('File successfully uploaded')
        return redirect(url_for('uploaded_file', filename=filename))
    else:
        flash('File type not allowed')
        return redirect(request.url)


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)