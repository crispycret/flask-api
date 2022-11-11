import jwt
import string
import datetime
from functools import wraps

from flask import request
from werkzeug.security import check_password_hash

from core import db
from core.auth import auth
from config import Configuration

from .models import User, Token
from .decorators import require_token, require_admin


def validate_and_create_user(data, privilege=0):
    ''' '''
    # Verify required infromation was provided
    if ('username' not in data): return {'status': 409, 'msg': 'username field required', 'body': {}}
    if ('email' not in data): return {'status': 409, 'msg': 'email field required', 'body': {}}
    if ('password' not in data): return {'status': 409, 'msg': 'password field required', 'body': {}}

    # Verify provided information is valid (meets constraints)

    ## validate username uses alphanumerical w/ underscores and periods and is not greater than the max length
    allowed_chars = [c for c in (string.ascii_letters + string.digits + '_.')]
    for c in data['username']:
        if (c not in allowed_chars): return {'status': 409, 'msg': 'invalid characters in username', 'body': {}}
    if (len(data['username']) > User.USERNAME_LENGTH):
        return {'status': 409, 'msg': f'username must be {User.USERNAME_LENGTH} character or less.', 'body': {}}

    ## validate email uses alphanumerical w/ underscores, periods, @ and is not greater than the max length
    allowed_chars.append('@')
    for c in data['username']:
        if (c not in allowed_chars): return {'status': 409, 'msg': 'invalid characters in email', 'body': {}}
    if (len(data['email']) > User.EMAIL_LENGTH):
        return {'status': 409, 'msg': f'email must be {User.EMAIL_LENGTH} characters or less.', 'body': {}}

    # Make sure required information provided is unique
    user = User.query.filter_by(email=data['email']).first()
    if (user): return {'status': 401, 'msg': f'email already in use.', 'body': {}}

    user = User.query.filter_by(username=data['username']).first()
    if (user): return {'status': 401, 'msg': f'username already in use.', 'body': {}}

    # Create use
    try: u = User.create(data['username'], data['email'], data['password'], privilege=privilege)
    except Exception as e: return {'status': 409, 'msg': 'could not create user', 'body': str(e)}

    # Add new user to the database and return the requests response.
    try:
        db.session.add(u)
        db.session.commit()
        return {'status': 200, 'msg': 'new user created', 'body': u.serialize}
    except: return {'status': 409, 'msg': 'could not save user to database', 'body': {}}


    # Verify email and username are unique
    return True




@auth.route('/users/create', methods=['POST'])
def create_user():
    ''' 
    Create a new user granted that all required information was provided and the email and username is unique. 
    Return the status of the request 
    '''
    data = request.get_json()
    return validate_and_create_user(data)



@auth.route('/admin/create', methods=['POST'])
def create_admin():
    ''' 
    Create a new user granted that all required information was provided and the email and username is unique.
    Unlike create_user() the provided information should be encoded using the applications Admin Secret Key and passed using
    the Authentication header. Return the status of the request 
    '''
    # Get the authroization token
    encoded_token = request.headers.get('Authorization')
    if (not encoded_token): return {'status': 409, 'msg': 'missing authentication token', 'body': {}}

    # Decode the authorization token to reveal the fields required to create the new user.
    try: data = jwt.decode(encoded_token, Configuration.ADMIN_SECRET_KEY, 'HS256')
    except: return {'status': 401, 'msg': 'invalid authentication token', 'body': {}}

    return validate_and_create_user(data, 1)
 


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




@auth.route('/login', methods=['POST'])
def login():
    ''' Return an authorization token upon validation of the email and password '''
    data = request.get_json()

    if ('password' not in data): 
        return {'status': 409, 'msg': 'password required', 'body': {}}
    if ('email' not in data and 'username' not in data): 
        return {'status': 409, 'msg': 'email or username required', 'body': {}}
    
    payload =  {k:v for k,v in data.items() if k in ['email', 'username']}
    user = User.query.filter_by(**payload).first()

    if (not user): return {'status': 404, 'msg': 'user not found', 'body': {}}
    if (not check_password_hash(user.password_hash, data['password'])):
        return {'status': 401, 'msg': 'password incorrect', 'body': {}}

    # Create Authentication Token Upon Success.
    created = datetime.datetime.now()
    expires = created + datetime.timedelta(hours=4)
    token_data = {'public_id': user.public_id, 'created': created.isoformat(), 'expires': expires.isoformat()}
    
    encoded_token = jwt.encode(token_data, Configuration.SECRET_KEY, 'HS256')
    token = Token(user_id=user.id, encoded_token=encoded_token)
    
    # Save to database
    db.session.add(token)
    db.session.commit()

    response = {'Authorization': encoded_token, 'user': user.serialize}
    return {'status': 200, 'msg': 'logged in', 'body': response}




@auth.route('/token/validate', methods=['GET'])
@require_token
def validate_token(user, token):
    return {'status': 200, 'msg': 'validated', 'body': {}}



@auth.route('/logout', methods=['POST'])
@require_token
def logout(user, token):
    ''' Confirm the removal of the provided authorization token. '''
    try:
        db.session.delete(token)
        db.session.commit()
        return {'status': 200, 'msg': 'logged out', 'body': {}}
    except: return {'status': 409, 'msg': 'could not properly logout', 'body': {}}
    


@auth.route('/admin/demote', methods=['PATCH'])
@require_admin
def demote_admin(user, token):
    ''' Demote the requester from admin privileges if the request is an admin'''
    try:
        user.privilege = 0
        db.session.commit()
        return {'status': 200, 'msg': 'demotion successful', 'body': {}}
    except: return {'status': 409, 'msg': 'could not demote privileges', 'body': {}}




@auth.route('/user/<username>/follow', methods=['POST'])
@require_token
def follow_user(username, user, token):
    ''' create a realtionship between the authenticated user and the specified user '''
    
    target_user = User.query.filter_by(username=username).first()
    if (not target_user): {'status': 404, 'msg': 'target user not found', 'body': {}}

    try:
        target_user.followers.append(user)
        db.session.commit()
    except: return {'status': 409, 'msg': 'could not follow user', 'body': {}}
    return {'status': 200, 'msg': f'following {username}', 'body': {}}
    


@auth.route('/user/<username>/followers', methods=['GET'])
def get_followers(username):
    ''' create a realtionship between the authenticated user and the specified user '''
    
    target_user = User.query.filter_by(username=username).first()
    if (not target_user): {'status': 404, 'msg': 'target user not found', 'body': {}}

    response = {
        'user': target_user.serialize,
        'followers': [follower.serialize for follower in target_user.followers] 
        
    }
    return {'status': 200, 'msg': f'follwers of {target_user.username}', 'body': response}
    




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
    
        





