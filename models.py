from flask_login import UserMixin
from datetime import datetime
import pytz
from . import db

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
