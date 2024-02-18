from flask import render_template, request, flash, redirect, url_for, abort
from app import app, db
from werkzeug.security import generate_password_hash, check_password_hash
from .models import Users, Groups
from flask_login import current_user, login_user, logout_user, login_required


@app.route('/')
def home():
  return render_template('home.html', title='Accueil', current_user=current_user)


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
      flash('Nom d\'utilisateur ou mot de passe incorrect', 'error')

  return render_template('login.html', title='Connexion')


@app.route('/register', methods=['GET', 'POST'])
def register():
  if request.method == 'POST':
    username = request.form.get('username')
    password = request.form.get('password')

    user = Users.query.filter_by(username=username).first()

    if user:
      flash('Ce nom d\'utilisateur est déjà pris', 'error')
    else:
      new_user = Users(username=username, password_hash=generate_password_hash(password, method='pbkdf2:sha256'))

      db.session.add(new_user)
      db.session.commit()
      login_user(new_user)
      flash('Votre compte a été créé', 'success')
      return redirect(url_for('home'))

  return render_template('register.html', title='Inscription')


@app.route('/logout')
def logout():
  logout_user()
  return redirect(url_for('home'))


@app.route('/dashboard')
@login_required
def dashboard():
  myGroupsAdmin = []
  myGroupsMember = []
  for group in Groups.query.all():
    if current_user.id in group.admins:
      myGroupsAdmin.append(group)
    if current_user.id in group.members:
      myGroupsMember.append(group)

  return render_template('dashboard.html', title='Tableau de bord', current_user=current_user, myGroupsAdmin=myGroupsAdmin, myGroupsMember=myGroupsMember)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
  if request.method == 'POST':
    username = request.form.get('username')
    password = request.form.get('password')
    delete = request.form.get('delete')

    if username:
      if current_user.username != username:
        if Users.query.filter_by(username=username).first():
          flash('Ce nom d\'utilisateur est déjà pris', 'error')
          return redirect(url_for('profile'))
        current_user.username = username
        flash('Votre nom d\'utilisateur a été modifié.', 'success')
    if password:
      current_user.set_password(password)
      flash('Votre mot de passe a été modifié.', 'success')
    if delete:
      db.session.delete(current_user)
      db.session.commit()
      flash('Votre compte a été supprimé.', 'success')
      return redirect(url_for('home'))

    db.session.commit()
    flash('Vos modifications ont été enregistrées.', 'success')
    return redirect(url_for('profile'))

  return render_template('profile.html', title='Profil')
    

@app.route('/create_group', methods=['POST'])
@login_required
def create_group():
  name = request.form.get('name')
  description = request.form.get('description')
  private = request.form.get('private')
  if private == 'on':
    private = True
  else:
    private = False

  if name:
    if Groups.query.filter_by(name=name).first():
      flash('Ce nom de groupe est déjà pris', 'error')
    else:
      new_group = Groups(name=name, description=description, private=private, admins=[current_user.id], members=[current_user.id])
      db.session.add(new_group)
      db.session.commit()
      flash('Le groupe a été créé.', 'success')
  else:
    flash('Le nom du groupe est requis', 'error')

  return redirect(url_for('dashboard'))


@app.route('/group/<int:id>')
@login_required
def group(id):
  group = Groups.query.get(id)
  if group is None:
    abort(404)
  is_admin = current_user.id in group.admins
  is_member = current_user.id in group.members  
  return render_template('group.html', title=group.name, group=group, is_admin=is_admin, is_member=is_member)


@app.route('/chercheGroup')
@login_required
def chercheGroup():
  groupsPublic = Groups.query.filter_by(private=False).all()
  return render_template('chercheGroup.html', title='Recherche de groupe', groupsPublic=groupsPublic)


@app.route('/join_group/<int:id>')
@login_required
def join_group(id):
  group = Groups.query.get(id)
  if group is None:
    abort(404)
  if current_user.id in group.members:
    return flash('Vous êtes déjà membre de ce groupe', 'error')
  if group.private:
    return flash('Ce groupe est privé', 'error')
  else:
    group.members = group.members + [current_user.id]
    db.session.commit()
    flash('Vous avez rejoint le groupe', 'success')
  return redirect(url_for('group', id=id))


@app.route('/leave_group/<int:id>')
@login_required
def leave_group(id):
  group = Groups.query.get(id)
  if group is None:
    abort(404)
  if current_user.id in group.admins:
    return flash('Vous êtes administrateur de ce groupe donc vous ne pouvez pas le quitter', 'error')
  if current_user.id not in group.members:
    return flash('Vous n\'êtes pas membre de ce groupe', 'error')
  else:
    listMembers = [member for member in group.members if member != current_user.id]
    group.members = listMembers
    db.session.commit()
    flash('Vous avez quitté le groupe', 'success')
  return redirect(url_for('group', id=id))


@app.route('/delete_group/<int:id>')
@login_required
def delete_group(id):
  group = Groups.query.get(id)
  if group is None:
    abort(404)
  if current_user.id not in group.admins:
    return flash('Vous n\'êtes pas administrateur de ce groupe', 'error')
  else:
    db.session.delete(group)
    db.session.commit()
    flash('Le groupe a été supprimé', 'success')
  return redirect(url_for('dashboard'))