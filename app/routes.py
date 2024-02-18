from flask import render_template, request, flash, redirect, url_for
from app import app, db
from werkzeug.security import generate_password_hash, check_password_hash
from .models import Users
from flask_login import current_user, login_user, logout_user

@app.route('/')
def home():
  return render_template('home.html', titre='Accueil', current_user=current_user)

@app.route('/about')
def about():
  return "Page à propos"

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = Users.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Nom d\'utilisateur ou mot de passe incorrect')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = Users.query.filter_by(username=username).first()

        if user:
            flash('Ce nom d\'utilisateur est déjà pris')
        else:
            new_user = Users(username=username, password_hash=generate_password_hash(password, method='pbkdf2:sha256'))

            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('home'))

    return render_template('register.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard')
def dashboard():
    if current_user.is_authenticated:
        return render_template('dashboard.html', titre='Tableau de bord', current_user=current_user)
    else:
        return redirect(url_for('login'))