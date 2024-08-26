from wsgiref.validate import validator
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash
import secrets, re
from werkzeug.security import generate_password_hash, check_password_hash
import db
import os
from werkzeug.utils import secure_filename
from jinja2 import Environment

def endswith_filter(value, extension):
    return value.endswith(extension)

env = Environment()
env.filters['endswith'] = endswith_filter
app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

UPLOAD_FOLDER = 'static/uploads/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif', 'mp4', 'avi', 'mov'])

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS 
def allowed_file_size(file):
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0, os.SEEK_SET)
    return file_size <= app.config['MAX_CONTENT_LENGTH']

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

@app.route('/')
def welcome_page():
    db.init_users()
    db.init_posts()
    db.init_comments()
    db.init_post_likes()
    return render_template('index.html')

@app.route('/user_panel')
def user_panel():
    if 'username' not in session:
        return redirect(url_for('login'))
    if session['user_type'] == 1:
        return redirect(url_for('author_panel'))
    posts = db.get_all_posts()
    comments = {post['id']: db.get_comments_by_post(post['id']) for post in posts}

    return render_template('user_panel.html', posts=posts, comments=comments)

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def update_user(id):
    if 'username' not in session:
        return redirect(url_for('login'))
    if session['user_type'] == 0 and id != session['user_id']:
        return redirect(url_for('user_panel'))
    if session['user_type'] == 1 and id != session['user_id']:
        return redirect(url_for('author_panel'))
    
    user = db.get_user_by_id(id)
    
    if user is None:
        return "User not found", 404

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        likes = request.form.get('likes', user['likes'])
        user_type = request.form.get('user_type', user['user_type'])

        if not username:
            return "Missing form data", 400
        
        if password != user['password']:
            hashed_password = generate_password_hash(password)
            db.update_user_with_password(username, hashed_password, likes, user_type, id)
        else:
            db.update_user_without_password(username, likes, user_type, id)
        
        return redirect(url_for('manage_admins'))
    
    return render_template('update_user.html', user=user)

@app.route('/add', methods=['GET', 'POST'])
def add_user():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        account_type = request.form.get('account_type')

        if not username or not password or account_type not in ['0', '1']:
            return "Invalid input", 400

        if db.get_user_by_username(username):
            return "Username already exists", 400

        # Server-side password validation
        strong_password_regex = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')
        if not strong_password_regex.match(password):
            return "Password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, one number, and one special character.", 400

        hashed_password = generate_password_hash(password)
        db.add_user(username, hashed_password, account_type)
        return redirect(url_for('welcome_page'))

    return render_template('add_user.html')

@app.route('/delete/<int:id>', methods=['POST'])
def delete_user(id):
    if 'username' not in session:
        return redirect(url_for('login'))
    if session['user_type'] == 0:
        return redirect(url_for('user_panel'))
    if session['user_type'] == 1:
        return redirect(url_for('author_panel'))
    db.delete_user(id)
    return redirect(url_for('manage_admins'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        user = db.get_user_by_username(username)

        if user is None or not check_password_hash(user['password'], password):
            error = 'Invalid credentials. Please try again.'
        else:
            session['username'] = username
            session['user_id'] = user['id']  # Ensure user_id is set
            session['user_type'] = user['user_type']
            # Redirect based on user type
            if user['user_type'] == 2:
                return redirect(url_for('manage_admins'))
            if user['user_type'] == 1:
                return redirect(url_for('author_panel'))
            else:
                return redirect(url_for('user_panel'))
    return render_template('login.html', error=error)

@app.route('/manage_admins', methods=['GET', 'POST'])
def manage_admins():
    admin_exists = db.check_if_admin_exists()

    if not admin_exists:
        if request.method == 'POST':
            new_username = request.form.get('username')
            password = request.form.get('password')
            
            if not new_username or not password:
                return "Missing form data", 400
            if db.get_user_by_username(new_username):
                return "Username already exists", 400            
            hashed_password = generate_password_hash(password)
            db.add_admin(new_username, hashed_password)
            session['username'] = new_username
            session['user_id'] = db.get_user_by_username(new_username)['id']
            session['user_type'] = 2  # Ensure user_id is set
            return redirect(url_for('manage_admins'))

        return render_template('create_admin.html')

    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    current_user = db.get_user_by_username(username)

    if current_user is None:
        return redirect(url_for('user_panel'))
    if current_user['user_type'] == 0:
        return redirect(url_for('user_panel'))
    elif current_user['user_type'] == 1:
        return redirect(url_for('author_panel'))
    # Fetch users for display and management
    users = db.get_users()

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        likes = request.form.get('likes')
        user_type = request.form.get('user_type')
        user_id = request.form.get('user_id')

        if not username or not user_id:
            return "Missing form data", 400

        if password:
            hashed_password = generate_password_hash(password)
            db.update_user_with_password(username, hashed_password, likes, user_type, user_id)
        else:
            db.update_user_without_password(username, likes, user_type, user_id)

        return redirect(url_for('manage_admins'))

    return render_template('manage_admins.html', users=users)
@app.route('/manage_posts', methods=['GET', 'POST'])
def manage_posts():
    user = db.get_user_by_username(session.get('username'))
    if user is None or user['user_type'] != 2:  # Check if the user is an admin
        return redirect(url_for('user_panel'))
    posts = db.get_all_posts()  # Fetch all posts
    return render_template('manage_posts.html', posts=posts, user=user)
@app.route('/author_panel')
def author_panel():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = db.get_user_by_username(session['username'])
    if user is None:
        return redirect(url_for('user_panel'))
    if session['user_type'] == 0:
        return redirect(url_for('user_panel'))
    elif session['user_type'] == 2:
        return redirect(url_for('manage_admins'))
    posts = db.get_posts_by_author(user['id'])
    return render_template('author_panel.html', posts=posts, user=user)

@app.route('/create_post', methods=['GET', 'POST'])
def create_post():
    if session['user_type'] == 0:
        return redirect(url_for('user_panel'))
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        media = request.files.get('media')
        
        file_url = None
        if media and allowed_file(media.filename) and allowed_file_size(media):
            file_url = db.get_max_post()
            media.save(os.path.join('static/uploads/posts', file_url))
        db.add_post(session['user_id'],title,content,file_url)
        return redirect(url_for('author_panel'))
    
    return render_template('create_post.html')

@app.route('/search', methods=['GET'])
def search_posts():
    if session['user_type'] == 1:
        return redirect(url_for('author_panel'))
    query = request.args.get('query', '')
    posts = db.search_posts(query)
    return render_template('search_results.html', posts=posts)

@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
def edit_post(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    user = db.get_user_by_username(session['username'])
    post = db.get_post_by_id(post_id)

    if post is None:
        return "Post not found", 404

    # Ensure the user has the right to edit the post
    if user['user_type'] == 1 and user['id'] != post['author_id']:
        return redirect(url_for('user_panel'))

    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        media = request.files.get('media')

        # Handle file upload
        file_url = post['file_url']  # Keep the existing file URL unless a new file is uploaded
        if media and allowed_file(media.filename) and allowed_file_size(media):
            file_url = post_id
            media.save(os.path.join(app.config['UPLOAD_FOLDER'] + '/posts', file_url))

        # Update the post in the database
        db.update_post(post_id, title, content)
        return redirect(url_for('manage_posts'))

    return render_template('edit_post.html', post=post)

@app.route('/delete_post/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    if 'username' not in session:
        flash('You need to be logged in to delete a post.')
        return redirect(url_for('login'))

    user = db.get_user_by_username(session['username'])
    if user is None or user['user_type'] not in [1, 2]:
        flash('You do not have permission to delete posts.')
        return redirect(url_for('user_panel'))

    conn = db.get_db_connection()

    # Fetch the post to delete
    post = conn.execute('SELECT id, author_id, file_url FROM posts WHERE id = ?', (post_id,)).fetchone()

    if post is None:
        flash('Post not found.')
        return redirect(url_for('user_panel'))

    # Check if the logged-in user is the author of the post or an admin
    if post['author_id'] != session['user_id'] and user['user_type'] != 2:
        flash('You do not have permission to delete this post.')
        return redirect(url_for('author_panel'))

    # Delete the post from the database
    conn.execute('DELETE FROM posts WHERE id = ?', (post_id,))
    conn.commit()

    # Delete the associated media file from the uploads folder, if any
    if post['file_url']:
        file_path = os.path.join(app.config['UPLOAD_FOLDER']+'/posts', post['file_url'])
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                flash('Post and associated media deleted successfully.')
            else:
                flash('Media file not found.')
        except Exception as e:
            flash(f'An error occurred while deleting the media file: {e}')
    if session['user_type'] == 2:
        return redirect(url_for('manage_posts'))
    return redirect(url_for('user_panel'))


@app.route('/like_post/<int:post_id>', methods=['POST'])
def like_post(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    user = db.get_user_by_username(session['username'])
    print(db.has_user_liked_post(session['user_id'],post_id))
    if not db.has_user_liked_post(session['user_id'],post_id):
        db.record_user_like(post_id, user['id'])
        db.increment_post_likes(post_id)
    return redirect(url_for('user_panel'))

@app.route('/comment/<int:post_id>', methods=['POST'])
def comment_on_post(post_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    user = db.get_user_by_username(session['username'])
    comment = request.form.get('comment')
    media = request.files.get('media')

    file_url = None
    if media and allowed_file(media.filename) and allowed_file_size(media):
        file_url = db.get_max_comment()
        media.save(os.path.join('static/uploads/comments', file_url))
    db.add_comment(post_id, user['username'], comment, file_url)
    return redirect(url_for('user_panel'))
@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/profile/<int:id>',methods=['GET','POST'])
def profile(id):
    if 'username' not in session:
        return redirect(url_for('login'))
    if id != session['user_id']:
        return redirect(url_for('user_panel'))
    if request.method == 'POST':
        username = request.form.get('username')
        photo = request.files.get('photo')  # Get the uploaded photo
        if not username:
            return "Missing form data", 400
        if username != session['username'] and db.get_user_by_username(username):
            return "Invalid username", 400
        if photo:
            if not allowed_file_size(photo):
                        return f"Unallowed size."
            elif not allowed_file(photo.filename):
                        return f"Unallowed extention."
            else:
                db.update_user_profile(id,id)
                photo.save(os.path.join(app.config['UPLOAD_FOLDER'] + '/profiles', id))
        db.update_username(username,id)
    user=db.get_user_by_id(id)
    return render_template('profile.html',user=user)

if __name__ == '__main__':
    app.run(debug=True)
