from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from models import db, User, PasswordEntry
from encryption import generate_key, encrypt_password, decrypt_password
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import os
import base64

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///password_manager.db'

# Initialize SQLAlchemy with the Flask app
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # redirect to login() - if user is not logged in

# check if the user exists in the database
def check_username(username):
    return User.query.filter_by(username=username).first() is not None

# check if the email exists in the database
def check_email(email):
    return User.query.filter_by(email=email).first() is not None

# load user mapped to the current session.
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    if 'username' in session:
        return render_template('home.html', username=session['username'])
    else:
        flash('Please log in to access your passwords.', 'warning')
        return redirect(url_for('login'))
    
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'] # from the html
        email = request.form['email'] # from the html
        password = request.form['password'] # from the html
        
        # check for the user details if is exists in the database.
        if check_username(username):
            flash("username already taken, please choose another.", 'danger')
            return redirect(url_for('register'))
        
        if check_email(email):
            flash("email is already taken, please choose another.", 'danger')
            return redirect(url_for('register'))    
        
        salt = os.urandom(16)
        password_hash = generate_password_hash(password)
        new_user = User(username=username, email=email, password_hash=password_hash, salt=base64.b64encode(salt).decode())
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_input = request.form['login'] # can be username or email
        password = request.form['password']
        user = User.query.filter((User.username == login_input) | (User.email == login_input)).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id # adding the user_id to the session
            login_user(user) # uses the build flask-login to handle the session
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    entries = PasswordEntry.query.filter_by(user_id=current_user.id).all() # PasswordEntry : model class
    decrypted_entries = []
    salt = base64.b64decode(current_user.salt)
    key = generate_key(current_user.password_hash, salt)

    for entry in entries:
        decrypted_password = decrypt_password(entry.encrypted_password, key)
        decrypted_entries.append({
            'id': entry.id,
            'service': entry.service,
            'username': entry.username,
            'password': decrypted_password  # include decrypted password
        })

    return render_template('dashboard.html', entries=decrypted_entries)

@app.route('/add_password', methods=['GET', 'POST'])
@login_required
def add_password():
    if request.method == 'POST':
        service = request.form['service']
        username = request.form['username']
        password = request.form['password']
        salt = base64.b64decode(current_user.salt)
        key = generate_key(current_user.password_hash, salt)
        encrypted_password = encrypt_password(password, key)
        new_entry = PasswordEntry(service=service, username=username, encrypted_password=encrypted_password, user_id=current_user.id)
        db.session.add(new_entry)
        db.session.commit()
        flash('Password added successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_password.html')

@app.route('/delete_password/<int:id>', methods=['GET', 'POST'])
@login_required
def delete_password(id):
    entry = PasswordEntry.query.get_or_404(id)
    if entry.user_id == current_user.id:
        db.session.delete(entry)
        db.session.commit()
        flash('Password entry deleted.', 'info')
    else:
        flash('Unauthorized action.', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('user_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all() # creates a db if it does not exists.
    app.run(debug=True)



