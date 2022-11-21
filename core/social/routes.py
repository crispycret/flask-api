from .. import db

from ..auth.models import User, Token
from ..auth.decorators import require_admin, require_token

from . import social



@social.route('/user/<username>/follow', methods=['POST'])
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
    


@social.route('/user/<username>/followers', methods=['GET'])
def get_followers(username):
    ''' create a realtionship between the authenticated user and the specified user '''
    
    target_user = User.query.filter_by(username=username).first()
    if (not target_user): {'status': 404, 'msg': 'target user not found', 'body': {}}

    response = {
        'user': target_user.serialize,
        'followers': [follower.serialize for follower in target_user.followers] 
        
    }
    return {'status': 200, 'msg': f'follwers of {target_user.username}', 'body': response}
    




@social.route('/user/<username>/block', methods=['POST'])
@require_token
def block_user(username, user):
    target_user = User.query.filter_by(username=username).first()
    if (not target_user): {'status': 404, 'msg': 'target user not found', 'body': {}}
    try:
        user.blocked.append(target_user)
        db.session.commit()
    except: return {'status': 409, 'msg': 'could not block user', 'body': {}}
    return {'status': 200, 'msg': f'{username} blocked', 'body': {}}
    
        







