from flask import render_template
from app import app

@app.route('/')
def home():
  return render_template('home.html', titre='Accueil')

@app.route('/about')
def about():
  return "Page à propos"