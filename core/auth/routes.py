import jwt
import string
import datetime
from functools import wraps

from flask import request
from werkzeug.security import check_password_hash

from core import db, twilio_client
from core.auth import auth
from config import Configuration

from .models import User, Token
from .decorators import require_token, require_admin


__docs__ = '''
    routes:
     * create_user - create a basic user and trigger a validate contact information event.
     * create_admin - create an admin user and trigger a validate contact information event.
     * update_user - update a user's info while protecting immutable variables based on privilege state.
     * login - validate a user's credentials and return a token used for authenticating user actions and events.
     * validate_token - return the authentication state of a token.
     * 
     * logout - destory the authenticity of an authentic token. 
     * get_user - retrieve
     * get_user_by_id - merge all alternative get_user_... functions with the the get_user function and complexify the request data.
     * * * * request data should define the search goals.
     * get_users - condense the get_user function into this route by setting a default limit of 1 (Implement Pagnation)

    functions:
    * validate_and_create_user - Highest level common function to create a user with unvalidated data.

'''



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



###########################################################################################################################


@auth.route('/create_user', methods=['POST'])
def create_user():
    ''' 
    Create a new user granted that all required information was provided and the email and username is unique. 
    Return the status of the request 
    '''
    data = request.get_json()
    return validate_and_create_user(data)



@auth.route('/create_admin', methods=['POST'])
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
 


###########################################################################################################################


@auth.route('/send_email_verification', methods=['POST'])
@require_token
def send_email_verification(user, token):
    ''' Provided the user's email is not already authenticated, send a verification email to the user. '''

    try:
        if (user.email_verified): 
            return {'status': 200, 'msg': f'{user.email} is already verified', 'body': {}}
    except:
        return {'status': 500, 'msg': f'email verification precheck failed (Unkown)', 'body': {}}

    try:
        verification = twilio_client.verify \
        .services(Configuration.TWILIO_VERIFY_SERVICE) \
        .verifications \
        .create(to=user.email, channel='email')
        return {'status': 201, 'msg': f'verifcation code sent to {user.email}', 'body': {}}
    except:
        return {'status': 500, 'msg': f'failed to send verification code to email', 'body': {}}


@auth.route('/confirm_email_verification', methods=['POST'])
@require_token
def confirm_email_verification(user, token):
    ''' Requires the value sent to the user email be returned. Upon success marks the user as email verified. '''
    data = request.get_json()

    if ('verification_code' not in data): 
        return {'status': 400, 'msg': f'verification_code is missing', 'body': {}}

    try:
        code = data['verification_code']
        check = twilio_client.verify \
            .services(Configuration.TWILIO_VERIFY_SERVICE) \
            .verification_checks.create(to=user.email, code=code)
    except:
        return {'status': 500, 'msg': f'error communicating with twilio.', 'body': {}}
        
    if (check.status == 'approved'):
        user.email_verified = True
        db.session.commit()
        return {'status': 200, 'msg': f'{user.email} is now verified', 'body': {'value': True}}

    return {'status': 401, 'msg': f'failed to verify {user.email}', 'body': {'value': False}}


###########################################################################################################################

@auth.route('/user')
@require_token
def authorized_get_user(user, token):
    ''' Upon validating user token retrieve user information that is sensitive. '''
    return {'status': 200, 'msg': 'user found', 'body': user.serialize}


#######
####### Get Public User Information Only (Unauthorized  )
#######
@auth.route('/user/<username>', methods=['GET'])
@require_token
def get_user(username):
    ''' get a user by username '''
    u = User.query.filter_by(username=username).first()
    if (not u): return {'status': 404, 'msg': 'user not found', 'body': {}}
    return {'status': 200, 'msg': 'user found', 'body': u.serialize}

@auth.route('/user/id/<id>', methods=['GET'])
@require_token
def get_user_by_id(id):
    ''' get a user by id '''
    u = User.query.filter_by(id=id).first()
    if (not u): return {'status': 404, 'msg': 'user not found', 'body': {}}
    return {'status': 200, 'msg': 'user found', 'body': u.serialize}


@auth.route('/user/email/<email>', methods=['GET'])
@require_token
def get_user_by_email(email):
    ''' get a user by email '''
    u = User.query.filter_by(email=email).first()
    if (not u): return {'status': 404, 'msg': 'user not found', 'body': {}}
    return {'status': 200, 'msg': 'user found', 'body': u.serialize}


###########################################################################################################################


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
    


###########################################################################################################################


@auth.route('/admin/demote', methods=['PATCH'])
@require_admin
def demote_admin(user, token):
    ''' Demote the requester from admin privileges if the request is an admin'''
    try:
        user.privilege = 0
        db.session.commit()
        return {'status': 200, 'msg': 'demotion successful', 'body': {}}
    except: return {'status': 409, 'msg': 'could not demote privileges', 'body': {}}



#########################################################################################################################

@auth.route('/delete_user', methods=['POST'])
@require_token
def delete_user(user, token):
    ''' Delete a user after validating the request for authentication '''
    try:
        db.session.delete(user)
        db.session.commit()
        return {'status': 200, 'msg': 'user deleted', 'body': {}}
    except: return {'status': 400, 'msg': 'could not delete user', 'body': {}}



