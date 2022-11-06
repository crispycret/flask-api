import jwt
import datetime
from functools import wraps

from flask import request

from core import db
from core.auth import auth
from config import Configuration

from .models import User, Token
from .decorators import require_token, require_admin




@auth.route('/user/create', methods=['POST'])
def create_user():
    ''' '''
    data = request.get_json()

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
    if ('email' not in data): 
        return {'status': 409, 'msg': 'email required', 'body': {}}
    
    user = User.query.filter_by(email=data['email']).first()
    if (not user): return {'status': 404, 'msg': 'user not found', 'body': {}}
    
    
    created = datetime.datetime.now()
    expires = created + datetime.timedelta(hours=4)
    data = {'public_id': user.public_id, 'created': created, 'expires': expires }
    
    token = jwt.encode(data, Configuration.ADMIN_SECRET_KEY, 'HS256')
    response = {'Authorization': token}
    return {'status': 200, 'msg': 'logged in', 'body': response}



@auth.route('/logout', methods=['POST'])
@require_token
def logout(user, token):
    ''' Confirm the removal of the provided authorization token. '''
    try:
        db.session.delete(token)
        return {'status': 200, 'msg': 'logged out', 'body': {}}
    except: return {'status': 409, 'msg': 'could not properly logout', 'body': {}}
    


@auth.route('/admin/demote', 'PATCH')
@require_admin
def demote_admin(user, token):
    ''' Demote the requester from admin privileges if the request is an admin'''
    try:
        user.privilege = 0
        db.session.commit()
        return {'status': 200, 'msg': 'demotion successful', 'body': {}}
    except: return {'status': 409, 'msg': 'could not demote privileges', 'body': {}}



