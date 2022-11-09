import jwt
from functools import wraps
from flask import request

from config import Configuration
from .models import User, Token

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
        
        try: data = jwt.decode(encoded_token, Configuration.SECRET_KEY, 'HS256')
        except Exception as e: return {'status': 401, 'msg': 'invalid authentication token', 'body': str(e)}

        token = Token.query.filter_by(encoded_token=encoded_token).first()
        if (not token): return {'status': 404, 'msg': 'token was not found', 'body': {}}

        if ('public_id' not in data):
            return {'status': 409, 'msg': 'missing public_id in decoded token', 'body': {}}
        
        user = User.query.filter_by(public_id=data['public_id']).first()
        if (not user): return {'status': 404, 'msg': 'user was not found', 'body': {}}

        return f(*args, user=user, token=token, **kwargs)
    return func


# @require_token
def require_admin(f):
    ''' restrict access to admin users '''
    @wraps(f)
    def func(*args, **kwargs):
        # SAME AS require_token
        if ('Authorization' not in request.headers): 
            return {'status': 404, 'msg': "Authentication token not provided.", 'body':{}}

        encoded_token = request.headers.get('Authorization')
        
        try: data = jwt.decode(encoded_token, Configuration.SECRET_KEY, 'HS256')
        except: return {'status': 401, 'msg': 'invalid authentication token', 'body': {}}

        token = Token.query.filter_by(encoded_token=encoded_token).first()
        if (not token): return {'status': 404, 'msg': 'token was not found', 'body': {}}

        if ('public_id' not in data):
            return {'status': 404, 'msg': 'user was not found', 'body': {}}
        
        user = User.query.filter_by().first()
        if (not user): return {'status': 404, 'msg': 'user was not found', 'body': {}}

        # Extension of require_token
        if (user.privilege == 0):
            return {'status': 401, 'msg': 'user does not have the privilege', 'body': {}}

        return f(*args, user=user, token=token, **kwargs)
    return func

