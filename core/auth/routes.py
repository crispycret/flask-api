import jwt
import datetime

from flask import request

from core import db
from core.auth import auth
from config import Configuration

from .models import User, Token

from functools import wraps

def require_token(f):
    ''' 
    Decorator to restrict access allowing only valid authentication tokens and other constraints.
    token and other constraints should be provided in the request headers. 
    '''
    @wraps(f)
    def func(*args, **kwargs):
        if ('Authorization' not in request.headers): 
            return {'status': 404, 'msg': "Authentication token not provided.", 'body':{}}

        encoded_token = request.headers.get('Authorization')
        
        try: data = jwt.decode(encoded_token, Configuration.ADMIN_SECRET_KEY, 'HS256')
        except: return {'status': 401, 'msg': 'invalid authentication token', 'body': {}}

        token = Token.query.filter_by(encoded_token=encoded_token).first()
        if (not token): return {'status': 404, 'msg': 'token was not found', 'body': {}}

        if ('user.public_id' not in data):
            return {'status': 404, 'msg': 'user was not found', 'body': {}}
        
        user = User.query.filter_by().first()
        if (not user): return {'status': 404, 'msg': 'user was not found', 'body': {}}

        return f(*args, user=user, **kwargs)
    return func






@auth.route('/user/create', methods=['POST'])
def create_user():
    ''' '''
    data = request.get_json()

    if ('username' not in data or 'email' not in data): return {'status': 409, 'msg': 'both username and email required', 'body': {}}
    if ('email' not in data): return {'status': 409, 'msg': 'email field required', 'body': {}}
    if ('password' not in data): return {'status': 409, 'msg': 'password field required', 'body': {}}

    try: u = User.new(data['email'], data['password'])
    except: return {'status': 409, 'msg': 'could not create user', 'body': {}}
    
    try: 
        db.session.add(u)
        db.session.commit()
        return {'status': 200, 'msg': 'new user created', 'body': u.serialize}
    except: return {'status': 409, 'msg': 'could not save user to database', 'body': {}}




@auth.route('/admin/create', methods=['POST'])
def create_admin():
    ''' Recieve an encoded admin token that contains the registration information of the new admin. '''
    encoded_token = request.headers.get('Authorization')
    if (not encoded_token): return {'status': 409, 'msg': 'missing authentication token', 'body': {}}

    try: data = jwt.decode(encoded_token, Configuration.ADMIN_SECRET_KEY, 'HS256')
    except: return {'status': 401, 'msg': 'invalid authentication token', 'body': {}}

    if ('email' not in data): return {'status': 409, 'msg': 'email field required', 'body': {}}
    if ('password' not in data): return {'status': 409, 'msg': 'password field required', 'body': {}}

    try: u = User.new(data['email'], data['password'], privilege=data['privilege'] or 1)
    except: return {'status': 409, 'msg': 'could not create user', 'body': {}}

    try:
        db.session.add(u)
        db.session.commit()
        return {'status': 200, 'msg': 'new admin created', 'body': u.serialize}
    except: return {'status': 409, 'msg': 'could not save user to database', 'body': {}}



@auth.route('/user/<username>', methods=['GET'])
def get_user(username):
    ''' get a user by username '''
    u = User.query.filter_by(username=username).first()
    if (not u): return {'status': 404, 'msg': 'user not found', 'body': {}}
    return {'status': 200, 'msg': 'user found', 'body': u.serialize}

@auth.route('/user/id/<id>', methods=['GET'])
def get_user_by_id(id):
    ''' get a user by id '''
    u = User.query.filter_by(id=id).first()
    if (not u): return {'status': 404, 'msg': 'user not found', 'body': {}}
    return {'status': 200, 'msg': 'user found', 'body': u.serialize}


@auth.route('/user/email/<email>', methods=['GET'])
def get_user_by_email(email):
    ''' get a user by email '''
    u = User.query.filter_by(email=email).first()
    if (not u): return {'status': 404, 'msg': 'user not found', 'body': {}}
    return {'status': 200, 'msg': 'user found', 'body': u.serialize}




@auth.route('/login')
def login():
    ''' Return an authorization token upon validation of the email and password '''
    data = request.get_json()

    if ('password' not in data): 
        return {'status': 409, 'msg': 'password required', 'body': {}}
    if ('email' not in data and 'username' not in data): 
        return {'status': 409, 'msg': 'email or username required', 'body': {}}

    
    payload =  {k:v for k,v in data.items() if k in ['email', 'password']}
    user = User.query.filter_by(**payload).first()

    if (not user): return {'status': 404, 'msg': 'user not found', 'body': {}}
    
    
    created = datetime.datetime.now()
    expires = created + datetime.timedelta(hours=4)
    data = {'public_id': user.public_id, 'created': created, 'expires': expires }
    
    token = jwt.encode(data, Configuration.ADMIN_SECRET_KEY, 'HS256')
    response = {'Authorization': token}
    return {'status': 200, 'msg': 'logged in', 'body': response}



@auth.route('/user/<username>/follow', methods=['POST'])
@require_token
def follow_user(username, user):
    ''' create a realtionship between the authenticated user and the specified user '''
    
    target_user = User.query.filter_by(username=username).first()
    if (not target_user): {'status': 404, 'msg': 'target user not found', 'body': {}}

    try:
        target_user.followers.append(user)
        db.session.commit()
    except: return {'status': 409, 'msg': 'could not follow user', 'body': {}}
    return {'status': 200, 'msg': f'following {username}', 'body': {}}
    

@auth.route('/user/<username>/block', methods=['POST'])
@require_token
def block_user(username, user):
    target_user = User.query.filter_by(username=username).first()
    if (not target_user): {'status': 404, 'msg': 'target user not found', 'body': {}}
    try:
        user.blocked.append(target_user)
        db.session.commit()
    except: return {'status': 409, 'msg': 'could not block user', 'body': {}}
    return {'status': 200, 'msg': f'{username} blocked', 'body': {}}
    
        


