from flask import Flask, Blueprint, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime
import pytz
from werkzeug.security import generate_password_hash, check_password_hash
import random, string
import os

db = SQLAlchemy()

app = Flask(__name__)

app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'

#app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql:'
#app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

login_manager = LoginManager()
#login_manager.login_view = 'login'
login_manager.init_app(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(25))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(1000))
    icon = db.Column(db.String(1000))
    friend_key = db.Column(db.String(100), unique=True)

class Friend(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user1 = db.Column(db.Integer)
    user2 = db.Column(db.Integer)

class FriendRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user1 = db.Column(db.Integer)
    user2 = db.Column(db.Integer)

class Chatroom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(25))
    chatroom_key = db.Column(db.String(100), unique=True)
    user1 = db.Column(db.Integer)
    user2 = db.Column(db.Integer, nullable=True)
    user3 = db.Column(db.Integer, nullable=True)
    user4 = db.Column(db.Integer, nullable=True)
    user5 = db.Column(db.Integer, nullable=True)

class Chat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chatroom_id = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, nullable=False)
    user_name = db.Column(db.String(25), nullable=False)
    text = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now(pytz.timezone('Asia/Tokyo')))

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    # since the user_id is just the primary key of our user table, use it in the query for the user
    return User.query.get(int(user_id))

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/user_settings')
def user_settings():
    return render_template('user_settings.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/signup', methods=['POST'])
def signup_post():
    name = request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('password')
    icon = 'default_icon.jpg'

    random_key = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    friend_key = random_key

    user_email = User.query.filter_by(email=email).first() # if this returns a user, then the email already exists in database

    if user_email: # if a user is found, we want to redirect back to signup page so user can try again
        flash('Email address already exists.')
        return redirect(url_for('signup'))

    # create a new user with the form data. Hash the password so the plaintext version isn't saved.
    new_user = User(name=name, email=email, password=generate_password_hash(password, method='sha256'), icon=icon, friend_key=friend_key)

    # add the new user to the database
    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('login'))

@app.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()

    # check if the user actually exists
    # take the user-supplied password, hash it, and compare it to the hashed password in the database
    if not user or not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        return redirect(url_for('login')) # if the user doesn't exist or password is wrong, reload the page

    # if the above check passes, then we know the user has the right credentials
    login_user(user, remember=remember)
    return redirect(url_for('mainpage'))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/mainpage')
@login_required
def mainpage():
    id = current_user.id
    chatrooms_user1 = Chatroom.query.filter_by(user1=id).all()
    chatrooms_user2 = Chatroom.query.filter_by(user2=id).all()
    chatrooms_user3 = Chatroom.query.filter_by(user3=id).all()
    chatrooms_user4 = Chatroom.query.filter_by(user4=id).all()
    chatrooms_user5 = Chatroom.query.filter_by(user5=id).all()

    return render_template(
        'mainpage.html',
        name=current_user.name,
        icon=current_user.icon,
        friend_key = current_user.friend_key,
        chatrooms_user1 = chatrooms_user1,
        chatrooms_user2 = chatrooms_user2,
        chatrooms_user3 = chatrooms_user3,
        chatrooms_user4 = chatrooms_user4,
        chatrooms_user5 = chatrooms_user5,
    )

@app.route('/mainpage/<string:chatroom_key>/')
@login_required
def chatroom(chatroom_key):
    id = current_user.id
    chatrooms_user1 = Chatroom.query.filter_by(user1=id).all()
    chatrooms_user2 = Chatroom.query.filter_by(user2=id).all()
    chatrooms_user3 = Chatroom.query.filter_by(user3=id).all()
    chatrooms_user4 = Chatroom.query.filter_by(user4=id).all()
    chatrooms_user5 = Chatroom.query.filter_by(user5=id).all()

    chatroom_key = chatroom_key
    chatroom_info = Chatroom.query.filter_by(chatroom_key=chatroom_key).first()
    user1 = User.query.filter_by(id=chatroom_info.user1).first()
    user2 = User.query.filter_by(id=chatroom_info.user2).first()
    user3 = User.query.filter_by(id=chatroom_info.user3).first()
    user4 = User.query.filter_by(id=chatroom_info.user4).first()
    user5 = User.query.filter_by(id=chatroom_info.user5).first()
    if not chatroom_info:
        flash('The chatroom does not exists. Please try again')
        return redirect(url_for('mainpage'))

    if  current_user.id not in [chatroom_info.user1,chatroom_info.user2,chatroom_info.user3,chatroom_info.user4,chatroom_info.user5]:
        return render_template(
            'chatroom_join.html',
            chatroom_id=chatroom_info.id,
            chatroom_name=chatroom_info.name,
            chatroom_key=chatroom_info.chatroom_key,
            chatroom_user1 = user1,
            chatroom_user2 = user2,
            chatroom_user3 = user3,
            chatroom_user4 = user4,
            chatroom_user5 = user5
        )

    chats = Chat.query.filter_by(chatroom_id=chatroom_info.id).all()

    return render_template(
        'chatroom.html',
        name=current_user.name,
        icon=current_user.icon,
        friend_key = current_user.friend_key,
        chatroom_id=chatroom_info.id,
        chatroom_name=chatroom_info.name,
        chatroom_key=chatroom_info.chatroom_key,
        chatrooms_user1 = chatrooms_user1,
        chatrooms_user2 = chatrooms_user2,
        chatrooms_user3 = chatrooms_user3,
        chatrooms_user4 = chatrooms_user4,
        chatrooms_user5 = chatrooms_user5,
        chatroom_user1 = user1,
        chatroom_user2 = user2,
        chatroom_user3 = user3,
        chatroom_user4 = user4,
        chatroom_user5 = user5,
        chats = chats,
    )

@app.route('/mainpage/<string:chatroom_key>/', methods=['POST'])
@login_required
def chat_post(chatroom_key):
    chatroom = Chatroom.query.filter_by(chatroom_key=chatroom_key).first()
    user_id = current_user.id
    user_name = current_user.name
    text = request.form.get('text')

    post = Chat(chatroom_id=chatroom.id, user_id=user_id, user_name=user_name, text=text)

    db.session.add(post)
    db.session.commit()

    id = current_user.id
    chatrooms_user1 = Chatroom.query.filter_by(user1=id).all()
    chatrooms_user2 = Chatroom.query.filter_by(user2=id).all()
    chatrooms_user3 = Chatroom.query.filter_by(user3=id).all()
    chatrooms_user4 = Chatroom.query.filter_by(user4=id).all()
    chatrooms_user5 = Chatroom.query.filter_by(user5=id).all()

    chatroom_key = chatroom_key
    chatroom_info = Chatroom.query.filter_by(chatroom_key=chatroom_key).first()
    user1 = User.query.filter_by(id=chatroom_info.user1).first()
    user2 = User.query.filter_by(id=chatroom_info.user2).first()
    user3 = User.query.filter_by(id=chatroom_info.user3).first()
    user4 = User.query.filter_by(id=chatroom_info.user4).first()
    user5 = User.query.filter_by(id=chatroom_info.user5).first()

    chats = Chat.query.filter_by(chatroom_id=chatroom_info.id).all()
    return render_template(
        'chatroom.html',
        name=current_user.name,
        icon=current_user.icon,
        friend_key = current_user.friend_key,
        chatroom_id=chatroom_info.id,
        chatroom_name=chatroom_info.name,
        chatroom_key=chatroom_info.chatroom_key,
        chatrooms_user1 = chatrooms_user1,
        chatrooms_user2 = chatrooms_user2,
        chatrooms_user3 = chatrooms_user3,
        chatrooms_user4 = chatrooms_user4,
        chatrooms_user5 = chatrooms_user5,
        chatroom_user1 = user1,
        chatroom_user2 = user2,
        chatroom_user3 = user3,
        chatroom_user4 = user4,
        chatroom_user5 = user5,
        chats = chats,
    )
@app.route('/change_name')#change_name.html作成
@login_required
def change_name():
    return render_template('change_name.html')

@app.route('/change_name', methods=['POST'])#名前を変更送信
@login_required
def change_name_update():
    user = User.query.get(current_user.id)

    user.name = request.form.get('name')

    db.session.commit()
    flash('Updated your name')
    return render_template('change_name.html')

@app.route('/change_password')
@login_required
def change_password():
    return render_template('change_password.html')#パスワードを変更するときのrender

@app.route('/change_password', methods=['POST'])#送るとき
@login_required#loginしないとページを読み込まないやつ
def change_password_update():
    user = User.query.get(current_user.id)#書いたやつを読み込む
    current_password = request.form.get('current_password')#設定したパスワードを読み込む
    password1 = request.form.get('password1')#1個目のパスワード
    password2 = request.form.get('password2')#2個目のパスワード
    if not check_password_hash(user.password, current_password):#設定していたパスワードが違った場合
        flash('Current password is difficult')#Current password is difficultと警告表示
        return render_template('change_password.html')

    if password1 != password2:#パスワード1とパスワード2が違った場合
        flash('New passwords is difficult. Please try again.')#New passwords is difficult. Please try again.と警告表示
        return render_template('change_password.html')

    user.password = generate_password_hash(password1, method='sha256')

    db.session.commit()#データベースにコミット
    flash('Updated your password')
    return render_template('change_password.html')

@app.route('/friend_key')#friend_key.html作成
@login_required
def friend_key():
    return render_template('friend_key.html',
    friend_key=current_user.friend_key)#friend_key取得

@app.route('/friend_list')
@login_required
def friend_list():
    friends1 = Friend.query.filter_by(user1=current_user.id).all()
    friends2 = Friend.query.filter_by(user2=current_user.id).all()
    maybe_friends = FriendRequest.query.filter_by(user2=current_user.id).all()
    friends_requested = FriendRequest.query.filter_by(user1=current_user.id).all()

    friends1_q = []
    friends2_q = []
    friends_requested_q = []
    for friend1 in friends1:
        friends1_q = User.query.filter_by(id=friend1.user2)

    for friend2 in friends2:
        friends2_q = User.query.filter_by(id=friend2.user1)

    for maybe_friend in maybe_friends:
        maybe_friends = User.query.filter_by(id=maybe_friend.user1)

    for friend_requested in friends_requested:
        friends_requested_q = User.query.filter_by(id=friend_requested.user2)

    check_fr = FriendRequest.query.all()
    check_f = Friend.query.all()
    return render_template(
        'friend_list.html',
        friends1=friends1_q,
        friends2=friends2_q,
        maybe_friends=maybe_friends,
        friends_requested=friends_requested_q,
        check_f=check_f,
        check_fr=check_fr,)

@app.route('/friend_list', methods=['POST'])
@login_required
def friend_add():
    friend_key = request.form.get('friend_key')

    friend_key_check = User.query.filter_by(friend_key=friend_key).first()
    if not friend_key_check:
        flash('The User has the friend key is not exists. Please try again')
        return redirect(url_for('friend_list'))

    if current_user == friend_key_check:
        flash('This friend key is YOURS. Please try again')
        return redirect(url_for('friend_list'))

    user1 = current_user.id
    user2 = User.query.filter_by(friend_key = friend_key).first()

    friend_request = FriendRequest(user1=user1, user2=user2.id)

    db.session.add(friend_request)
    db.session.commit()

    return redirect(url_for('friend_list'))

@app.route('/maybe_to_friend', methods=['POST'])
@login_required
def maybe_to_friend():
    user1 = current_user.id
    user2 = request.form.get('maybe_friend_id')

    maybe_to_friend = Friend(user1=user1, user2=user2)

    delete_request_friend = FriendRequest.query.filter_by(user1 = user2, user2 = user1).first()

    db.session.add(maybe_to_friend)
    db.session.delete(delete_request_friend)
    db.session.commit()

    return redirect(url_for('friend_list'))

@app.route('/make_chatroom_in_friend_list', methods=['POST'])
@login_required
def make_chatroom_in_friend_list():
    chatroom_user2_id = request.form.get('make_chatroom_in_friend_list')

    user1 = User.query.filter_by(id=current_user.id).first()
    user2 = User.query.filter_by(id=chatroom_user2_id).first()
    name = '' + str(user1.name) + ' and ' + str(user2.name) + "'s Chatroom"

    random_key = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    chatroom_key = random_key

    make_chatroom_in_friend_list = Chatroom(name=name, chatroom_key=chatroom_key, user1=user1.id, user2=user2.id)

    db.session.add(make_chatroom_in_friend_list)
    db.session.commit()

    return redirect(url_for('chatroom', chatroom_key=chatroom_key))

@app.route('/chatroom_join', methods=['POST'])
@login_required
def chatroom_join():
    chatroom_id = request.form.get('chatroom_id')

    chatroom = Chatroom.query.filter_by(id=chatroom_id).first()

    if chatroom.user5:
        flash('The members of this room are full. Search another one.')
        return redirect(url_for('mainpage'))

    if chatroom.user4:
        chatroom.user5 = current_user.id
    elif chatroom.user3:
        chatroom.user4 = current_user.id
    elif chatroom.user2:
        chatroom.user3 = current_user.id
    elif chatroom.user1:
        chatroom.user2 = current_user.id

    db.session.commit()
    return redirect(url_for('mainpage'))
