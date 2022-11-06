
import datetime

from .. import db


class Post(db.Model):
    __tablename__ = 'post'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    title = db.Column(db.String(126), unique=True, nullable=False)
    body = db.Column(db.LargeBinary, nullable=False)
    created_at = db.Column(db.DateTime(), nullable=False)
    updated_at = db.Column(db.DateTime(), nullable=True)

    comments = db.relationship('Comment', backref='post', lazy=True, cascade='all, delete-orphan')

    @property
    def serialize(self):
        return {
            'id': self.id, 
            'title': self.title,
            'body': self.body.decode("utf-8"),
            'created_at': self.created_at,
            'updated_at': self.updated_at
        }

    @staticmethod
    def create(data={}):
        ''' Return a post using the given data or return None if a post could not be created. '''
        # Hard code the fields for now (make abstract to always implement these methods)

        if ('created_at' not in data):
            data['created_at'] = datetime.datetime.now()
        
        data['body'] = bytes(data['body'], 'UTF-8')

        try: return Post(**data)
        except: return None


    def update(self, data={}):
        ''' Allow the modification of the object. '''

        if ('updated_at' not in data.keys()):
            self.updated_at = datetime.datetime.now()
        else:
            self.updated_at = data['updated_at']

        if ('body' in data.keys()):
            self.body = bytes(data['body'], 'UTF-8')

        if('title' in data.keys()):
            self.title = data['title']

        return self





class Comment(db.Model):
    ''' Comment of a post. '''

    post_id = db.Column(db.Integer, db.ForeignKey('post.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime(), nullable=False)
    updated_at = db.Column(db.DateTime(), nullable=True)


    @property
    def serialize(self):
        return {
            'id': self.id,
            'post_id': self.post_id,
            'body': self.body,
            'created_at': self.created_at,
            'updated_at': self.updated_at
        }

    @staticmethod
    def create(data):
        if ('created_at' not in data): 
            data['created_at'] = datetime.datetime.now()
        
        try: return Comment(**data)
        except: return None


    def update(self, data):
        if ('updated_at' not in data):
            data['updated_at'] = datetime.datetime.now()        

        self.updated_at = data['updated_at']

        if ('post_id' in data): self.post_id = data['post_id']
        if ('body' in data): self.body = data['body']

        return self




