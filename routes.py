import datetime

from app import app, database
from functools import wraps
from flask import render_template, request, redirect, url_for, session, flash, abort, jsonify
from models import User, Relationship, Message
from peewee import IntegrityError
from hashlib import md5

@app.before_request
def before_request():
    database.connect()

@app.after_request
def after_request(response):
    database.close()
    return response


# ================================
# Helper Function ================
# ================================

def auth_user(user):
    session['logged_in'] = True
    session['user_id']   = user.id
    session['username']  = user.username
    flash('Kamu berhasil login sebagai ' + session['username'])

def get_current_user():
    if session.get('logged_in'):
        return User.get(User.id == session['user_id'])


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def redirect_if_loggedin (f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('logged_in'):
            return redirect(url_for('homepage'))
        return f(*args, **kwargs)
    return decorated_function

def getUserOrAbort(username):
    try:
        return User.get(User.username == username)
    except User.DoesNotExist:
        abort(404)


@app.context_processor
def _inject_user():
    return {'active_user' : get_current_user()}

# ================================
# # Routing Auth =================
# ================================
@app.route('/')
@login_required
def homepage():  
    # //stream tweet from own tweet & following  
    user = get_current_user()
    messages =(Message.select()
                       .where((Message.user << user.following()) |
                               (Message.user == user.id))
                       .order_by(Message.published_at.desc()).limit(2)
                )
                
    return render_template('indexx.html', messages = messages)

@app.route('/loadMore/<int:pageNum>')
def loadMore(pageNum):
    user = get_current_user()
    messages = {}

    for message in (Message.select()
                        .where((Message.user << user.following()) |
                               (Message.user == user.id))
                        .order_by(Message.published_at.desc())
                        .paginate(pageNum, 2)):
        messages[message.id] = {
                                'content': message.content,
                                'username': message.user.username,
                              }                
                           
    return jsonify(messages)
@app.route('/register', methods=['GET', 'POST'])
@redirect_if_loggedin
def register():
    if request.method == 'POST' and request.form['username']:
        try:
            with database.atomic():
                user = User.create(
                    username = request.form['username'],
                    password = md5(request.form['password'].encode('utf-8')).hexdigest(),
                    email    = request.form['email']
                 )
            
            auth_user(user)            
            return redirect(url_for('homepage'))

        except IntegrityError:
            flash('user sudah terdaftar')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@redirect_if_loggedin
def login():
    if request.method == 'POST' and request.form['username']:
        try:
            hashed_pass = md5(request.form['password'].encode('utf-8')).hexdigest()
            user = User.get(
                            (User.username == request.form['username']) &
                            (User.password == hashed_pass)) 
        
        except User.DoesNotExist:     
            return ('user atau password salah')

        else:
            auth_user(user)
            return redirect(url_for('homepage'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('Logout berhasil!')
    return redirect(url_for("homepage"))

# ================================
# # Routing Tweet ================
# ================================

@app.route('/new', methods=['GET', 'POST'])
@login_required
def create():
    user = get_current_user()
    if request.method == 'POST' and request.form['content']:
        message = Message.create(
            user = user,
            content = request.form['content']
        )

        flash('status kamu sudah terupdate!')
        return redirect(url_for('user_profile', username=user.username))

    return render_template('newpost.html')        

@app.route('/user/<username>')
def user_profile(username):
    user = getUserOrAbort(username)
    messages = user.messages.order_by(Message.published_at.desc())
    return render_template('profilee.html', messages=messages, user=user)

@app.route('/user_follow/<username>', methods=["POST"])
def user_follow(username):
    user = getUserOrAbort(username)
    try:
        with database.atomic():
            Relationship.create(
                from_user = get_current_user(),
                to_user = user,
            )     
    except IntegrityError:
        pass

    flash("Kamu berhasil memfollow " + username)
    return redirect(url_for('user_profile', username=username))        
# unfollow
@app.route('/user_unfollow/<username>', methods=["POST"])
def user_unfollow(username):
    user = getUserOrAbort(username)
    (Relationship.delete()
        .where(
            (Relationship.from_user == get_current_user()) &
            (Relationship.to_user == user))
        .execute())    

    flash("Kamu berhasil unfollow " + username)
    return redirect(url_for('user_profile', username=username))        

@app.route('/user/<username>/following')
def show_following(username):
        user = getUserOrAbort(username)
        return render_template('user_list.html', users = user.following())          

@app.route('/user/<username>/followers')
def show_followers(username):
        user = getUserOrAbort(username)
        return render_template('user_list.html', users = user.followers())          