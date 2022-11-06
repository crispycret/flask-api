import datetime
from flask import request

from .. import db
from ..auth.decorators import require_admin, require_token


from . import blog
from . import models



@blog.route("/post/create", methods=['POST'])
@require_admin
def create_post(admin, token):
    ''' Create a blog post and save to the database. '''

    data = request.get_json()
    data['user_id'] = admin.id

    # // Before creating the post check to see if the title is unique
    try:
        post = models.Post.query.filter_by(title=data['title']).first()
        if (post):
            return {'status': 409, 'msg': 'post not created', 'body': "Post with the same title already exists"}
    except Exception as e:
        # Not expecting an error yet
        return {'status': 400, 'msg': 'post not created', 'body': str(e)}

    try:
        post = models.Post.create(data)
        db.session.add(post)
        db.session.commit()
        return {'status': 200, 'msg': 'post created', 'body': post.serialize}
    except Exception as e:
        return {'status': 400, 'msg': 'post not created', 'body': str(e)}


@blog.route('/post/all')
def get_posts():
    ''' Get all posts. Use pagenativation was database gets large. '''
    # Implement pagnagation
    posts = models.Post.query.order_by(models.Post.created_at.desc()).limit(10) #.all()

    # Hide private posts unless requester provides admin authentication token.
    posts = [post.serialize for post in posts]
    count = len(posts)
    data = {'posts': posts}
    return {'status': 200, 'msg': f'{count} posts found', 'body': data} 


@blog.route('/post/<id>', methods=['GET'])
def get_post(id):
    ''' retrieve a blog post from the database '''
    try:
        post = models.Post.query.filter_by(id=id).first()

        if (not post): 
            raise Exception(f'Could not find post with id {id}')

        response = post.serialize                    
        return {'status': 200, 'msg': 'post found', 'body': post.serialize} 

    except Exception as e:
        return {'status': 404, 'msg': 'post not found', 'body': str(e)} 

  




@blog.route('/post/<id>/delete', methods=['DELETE'])
@require_admin
def delete_post(id, admin, token):
    ''' remove a blog post from the database '''
    try:
        post = models.Post.query.filter_by(id=id).first()
        if (not post): raise Exception(f'Could not find post with id {id}')
        
        db.session.delete(post)
        db.session.commit()
        return {'status': 200, 'msg': 'post deleted', 'body': {}}
    except Exception as e:
        return {'status': 400, 'msg': 'post not deleted', 'body': str(e)}



@blog.route('/post/<id>/update', methods=['PATCH'])
@require_admin
def update_post(id, admin, token):
# def update_post(id):
    ''' update an existing blog post '''

    data = request.get_json()

    try:
        post = models.Post.query.filter_by(id=id).first()
        if (not post): 
            return {'status': 400, 'msg': 'post not found', 'body': str(e)}
        
        post.update(data)
        
        post = db.session.merge(post)
        db.session.commit()
        return {'status': 200, 'msg': 'post updated', 'body': post.serialize}
    except Exception as e:
        return {'status': 400, 'msg': 'post not updated', 'body': str(e)}








@blog.route('/post/<post_id>/comment/create', methods=['POST'])
@require_token
def create_comment(post_id, user, token):
    ''' Create a new comment for a given post '''
    data = request.get_json()
    data['post_id'] = post_id
    try:
        post = models.Post.query.filter_by(id=post_id).first()
        if (not post): raise Exception(f'Could not find post with id {post_id}')
        
        comment = models.Comment.create(data)
        db.session.add(comment)
        db.session.commit()
        return {'status': 200, 'msg':'comment created', 'body': comment.serialize}
    except Exception as e:
        return {'status': 400, 'msg':'comment not created', 'body': str(e)}


@blog.route('/post/<post_id>/comment/<id>', methods=['GET'])
def get_comment(post_id, id):
    ''' Retireve the comment with the matching post_id and id '''
    try:
        comment = models.Comment.query.filter_by(post_id=post_id, id=id).first()
        if (not comment): raise Exception(f'Could not find comment with (post_id, id) ({post_id}, {id})')
        
        return {'status': 200, 'msg':'comment found', 'body': comment.serialize}
    except Exception as e:
        return {'status': 400, 'msg':'comment not found', 'body': str(e)}


@blog.route('/post/<post_id>/comment/<id>/update', methods=['PATCH'])
@require_token
def update_comment(post_id, id, user, token):
    ''' Update the comment with the matching post_id and id '''
    data = request.get_json()

    try:
        comment = models.Comment.query.filter_by(post_id=post_id, id=id).first()
        if (not comment): raise Exception(f'Could not find comment with (post_id, id) ({post_id}, {id})')

        comment.update(data)

        db.session.add(comment)
        db.session.commit()
        return {'status': 200, 'msg':'comment updated', 'body': comment.serialize}
    except Exception as e:
        return {'status': 400, 'msg':'comment not updated', 'body': str(e)}



@blog.route('/post/<post_id>/comment/<id>/delete', methods=['DELETE'])
@require_token
def delete_comment(post_id, id, user, token):
    ''' delete the comment with matching post_id and id '''
    try:
        comment = models.Comment.query.filter_by(post_id=post_id, id=id).first()
        if (not comment): raise Exception(f'Could not find comment with (post_id, id) ({post_id}, {id})')

        db.session.delete(comment)
        db.session.commit()
        return {'status': 200, 'msg':'comment deleted', 'body': {}}
    except Exception as e:
        return {'status': 400, 'msg':'comment not deleted', 'body': str(e)}




@blog.route('/post/<post_id>/comments')
def get_comments(post_id):
    ''' return all the comments realted to a post. '''
    try:
        comments = models.Comment.query.filter_by(post_id=post_id).all()
        return {'status': 200, 'msg':f'{len(comments)} comments found', 'body': [c.serialize for c in comments]}
    except Exception as e:
        return {'status': 400, 'msg':'problem loading comments', 'body': str(e)}





