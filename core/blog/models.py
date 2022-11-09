
import datetime

from .. import db


class Post(db.Model):
    __tablename__ = 'post'
    # __table_args__ = (
    #     db.UniqueConstraint(user_id, title, name='unique_user_title'),
    # )


    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    title = db.Column(db.String(126), nullable=False)
    body = db.Column(db.LargeBinary, nullable=False)
    created_at = db.Column(db.DateTime(), nullable=False)
    updated_at = db.Column(db.DateTime(), nullable=True)

    private = db.Column(db.Boolean, nullable=False, default=False)
    draft = db.Column(db.Boolean, nullable=False, default=False)

    comments = db.relationship('Comment', backref='post', lazy=True, cascade='all, delete-orphan')

    db.UniqueConstraint(user_id, title, name='unique_user_title'),

    @property
    def serialize(self):
        return {
            'id': self.id,
            'user_id': self.user_id, 
            'title': self.title,
            'body': self.body.decode("utf-8"),
            'private': self.private,
            'draft': self.draft,
            'created_at': self.created_at,
            'updated_at': self.updated_at
        }

    @staticmethod
    def create(user_id, title, body, created_at=None, updated_at=None, private=False, draft=False):
        ''' Return a post using the given data or return None if a post could not be created. '''
        # Hard code the fields for now (make abstract to always implement these methods)

        if (not created_at):
            created_at = datetime.datetime.now()
        
        body = bytes(body, 'UTF-8')

        try: return Post(
            user_id=user_id, title=title, body=body, 
            created_at=created_at, updated_at=updated_at,
            private=private, draft=draft
        )
        except: return None


    def update(self, data={}):
        ''' Allow the modification of the object. '''

        if ('updated_at' not in data.keys()): self.updated_at = datetime.datetime.now()
        else: self.updated_at = data['updated_at']

        if('title' in data.keys()): self.title = data['title']
        if ('body' in data.keys()): self.body = bytes(data['body'], 'UTF-8')
        if('private' in data.keys()): self.private = data['private']
        if('draft' in data.keys()): self.draft = data['draft']

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
            'user_id': self.user_id,
            'body': self.body,
            'created_at': self.created_at,
            'updated_at': self.updated_at
        }

    @staticmethod
    def create(user_id, post_id, body, created_at=None, updated_at=None):
        if (not created_at): 
            created_at = datetime.datetime.now()
        
        try: return Comment(user_id=user_id, post_id=post_id, body=body, created_at=created_at, updated_at=updated_at)
        except: return None


    def update(self, data):
        if ('updated_at' not in data):
            data['updated_at'] = datetime.datetime.now()        

        self.updated_at = data['updated_at']

        # if ('post_id' in data): self.post_id = data['post_id']
        if ('body' in data): self.body = data['body']

        return self




