
import uuid
from sqlalchemy import Table, Column, ForeignKey

from werkzeug.security import generate_password_hash, check_password_hash

from .. import db

from .utils import uuid32, uuid64, unique_generator


class Token(db.Model):
    ''' User generated token holding some data that is used to validate the user. '''
    __tablename__ = 'token'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encoded_token = db.Column(db.String(256), nullable=False, unique=True)

    @property
    def serialize(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'encoded_token': self.encoded_token
        }



# https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-viii-followers-contacts-and-friends
# Many-to-Many Relationship is the relation of a user having many followers and a user following many users.
# This requires the use of an association table.
# Because the second entity in the relationship is also of users this type of relationship is called a 
# self-referential relationship. 
# The use of an auxiliary table has no data other than the foreign keys.

followers = db.Table('followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('followed_id', db.Integer, db.ForeignKey('user.id'))
)

blockers = db.Table('blockers',
    db.Column('blocker_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('blocked_id', db.Integer, db.ForeignKey('user.id'))
)



class User(db.Model):
    
    USERNAME_LENGTH = 64
    EMAIL_LENGTH = 64

    ''' A user object containing an array of fields and relationships '''
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(USERNAME_LENGTH), nullable=False, unique=True)
    email = db.Column(db.String(128), nullable=False, unique=True)
    password_hash = db.Column(db.String(256), nullable=False)
    public_id = db.Column(db.String(32), nullable=False, unique=True)
    private_id = db.Column(db.String(64), nullable=False, unique=True)
    privilege = db.Column(db.Integer, default=0)
    email_verified = db.Column(db.Boolean, nullable=True, default=False)

    # Relationships
    tokens = db.relationship('Token', backref='user', lazy=True, cascade='all, delete-orphan')

    # relation of users who have blocked this user
    blocked = db.relationship(
        "User", secondary=blockers,
        primaryjoin=(blockers.c.blocker_id == id), 
        secondaryjoin=(blockers.c.blocked_id == id), 
        backref=db.backref('blockers', lazy='dynamic'), lazy='dynamic'
    )

    # relation of users who have followed this user
    followed = db.relationship(
        'User', secondary=followers,
        primaryjoin=(followers.c.follower_id == id),
        secondaryjoin=(followers.c.followed_id == id),
        backref=db.backref('followers', lazy='dynamic'), lazy='dynamic'
    )

    posts = db.relationship('Post', backref='user', lazy=True, cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='user', lazy=True, cascade='all, delete-orphan')


    @property
    def serialize(self):
        return {
            'id': self.id, 'username': self.username, 'email': self.email, 
            'public_id': self.public_id, 'privilege': self.privilege,
            'email_verified': self.email_verified
        }

    @staticmethod
    def create(username, email, password, privilege=0):
        ''' '''
        password_hash = generate_password_hash(password)
        public_id = User.generate_public_id()
        private_id = User.generate_private_id()
        u = User( username=username, privilege=privilege,
            email=email, password_hash=password_hash,
            public_id=public_id, private_id=private_id, 
        )
        return u


    @staticmethod
    def generate_public_id():
        ''' A public '''
        return unique_generator(User, 'public_id', uuid32())

    @staticmethod
    def generate_private_id():
        ''' '''
        return unique_generator(User, 'public_id', uuid64())



