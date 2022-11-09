import datetime
from flask import request

from .. import db
from ..auth.models import User
from ..auth.decorators import require_admin, require_token

from . import blog
from .models import Post, Comment 


'''
Instead of having so many routes try to condense some

get_comments, get_comments_by_id and get_comments_by_ids

can be combined into get_comments with the path /posts/comments/

This method should expect a request json that specifies the serach parameters

if the json is empty or null return all comments
otherwise expect a list of comment ids to return.
Provide only a single id in the list if you want only a single comment.
'''


'''

A Single method could be used that checks for what data is being used to find comments.
get_comments ()
request = {
    ids: []
    post_ids: []
    user_ids: []
}

* GET /blog/comments
* get_comments()
request = {
    ids: [1,5,4]
}
response = {
    comments: [<Comment 1>, <Comment 5>, <Comment 4>]
}


* GET /blog/posts/comments
* get_comments_by_posts()
request = {
    post_ids: [1, 2, 3]
}
response = {
    comments: [<Comment 1>, <Comment 5>, <Comment 8>]
}



* GET /blog/posts/comments/
* get_comments_by_posts()
request = {
    post_ids: [1, 2, 3]
}
response = {
    comments: [<Comment 1>, <Comment 5>, <Comment 8>]
}
'''




'''
 # Routes:

    * POST /post/create
    * DELETE /post/<id>/delete
    * PATCH /post/<id>/update
 
    * GET /posts
    * GET /post/<id>
    * GET /user/<user_id>/posts
    * GET /users/ids/posts
    * GET /user/<user_id>/post/<title>

    * POST /post/<post_id>/comment/create
    * PATCH /post/<post_id>/comment/<id>/update
    * DELETE /post/<post_id>/comment/<id>/delete

    * GET /post/comments
    * GET /post/comment/<id>
    * GET /post/comment/ids
    * GET /post/<post_id>/comments
    * GET /posts/post_ids/comments
    * GET /user/<user_id>/posts/comments
    * GET /<username>/posts/comments
    * GET /<username>/post/<id>/comments
    * GET /<username>/post/<id>/comment/<id>


 # Methods:

    * create_post(user, token)
    * delete_post(id, user, token)
    * update_post(id, user, token)

    * get_posts()
    * get_post_by_id(id)
    * get_posts_by_user(id)
    * get_posts_by_users(ids)
    * get_post_by_user_id_and_title(user_id, title)
 
    * create_comment(post_id, user, token)
    * update_comment(post_id, id, user, token)
    * delete_comment(post_id, id, user, token)

    * get_comments()
    * get_comments_by_id(id)
    * get_comments_by_ids(ids)
    * get_comments_by_post(post_id)
    * get_comments_by_posts(post_ids)
    * get_comments_by_user_id(user_id)
    * get_comments_by_user_ids(user_ids)
    * get_comments_by_user_id_and_post_id(user_id, post_id)


'''




######################################################################################################################
######################################################################################################################


@blog.route('/post/create', methods=['POST'])
@require_token
def create_post(user, token):
    ''' Create a blog post and save to the database. '''

    data = request.get_json()
    data['user_id'] = user.id

    if ('title' not in data): return {'status': 409, 'msg': 'missing required `title` field', 'body': {}}
    if ('body' not in data): return {'status': 409, 'msg': 'missing required `body` field', 'body': {}}


    # // Before creating the post check to see if the title is unique to this user
    try:
        post = Post.query.filter_by(user_id=user.id, title=data['title']).first()
        if (post):
            return {'status': 409, 'msg': 'post title already exists for this user', 'body': {}}
    except Exception as e:
        # Not expecting an error yet
        return {'status': 403, 'msg': 'post not created, Unkown error.', 'body': {}}

    try:
        post = Post.create(**data)
    except Exception as e: 
        return {'status': 400, 'msg': 'could not create post', 'body': str(e)}

    try:
        db.session.add(post)
        db.session.commit()
        return {'status': 200, 'msg': 'post created', 'body': post.serialize}
    except Exception as e:
        return {'status': 400, 'msg': 'could not add post to database', 'body': str(e)}




@blog.route('/post/<id>/delete', methods=['DELETE'])
@require_token
def delete_post(id, user, token):
    ''' remove a blog post from the database '''
    try:
        post = Post.query.filter_by(id=id).first()
        if (not post): raise Exception(f'Could not find post with id {id}')
        
        db.session.delete(post)
        db.session.commit()
        return {'status': 200, 'msg': 'post deleted', 'body': {}}
    except Exception as e:
        return {'status': 400, 'msg': 'post not deleted', 'body': str(e)}



@blog.route('/post/<id>/update', methods=['PATCH'])
@require_token
def update_post(id, user, token):
    ''' update an existing blog post '''

    data = request.get_json()

    try:
        post = Post.query.filter_by(id=id).first()
        if (not post): 
            return {'status': 400, 'msg': 'post not found', 'body': str(e)}
        
        post.update(data)
        
        post = db.session.merge(post)
        db.session.commit()
        return {'status': 200, 'msg': 'post updated', 'body': post.serialize}
    except Exception as e:
        return {'status': 400, 'msg': 'post not updated', 'body': str(e)}


######################################################################################################################
######################################################################################################################

@blog.route('/posts/last/<n>', methods=['GET'])
def get_last_n_posts(n):
    # posts = Post.query.order_by(Post.created_at.desc()).limit(10)
    
    posts = Post.query.order_by(Post.created_at.desc()
    ).filter_by(prive=False, draft=False).limit(10)

    if (posts == [] or posts == None):
        return {'status': 404, 'msg': 'no posts found', 'body': {}}

    body = {'posts': [post.serialize for post in posts]}
    return {'status': 200, 'msg': f'posts found', 'body': body} 


@blog.route('/posts', methods=['GET'])
def get_posts():
    ''' Get all posts. Use pagenativation was database gets large. '''
    try: data = request.get_json()
    except:data = {}
        
    posts = []

    # Get all posts
    if ('ids' not in data): posts = Post.query.all()

    # Get all posts
    elif (data['ids'] == []): posts = Post.query.all()

    # Provided ids attribute is not a list
    elif (type(data['ids']) is not list):
        return {'status': 409, 'msg': 'ids must be a list of post ids.', 'body':{}}
    
    else:
        # Provided ids attribute is not a list of integers
        for id in data['ids']:
            if (type(id) is not int):
                return {'status': 409, 'msg': 'ids must be a list of post ids represented by integers.', 'body':{}}

        # Get all posts with the requested ids
        posts = db.session.query(Post).filter(Post.id.in_(data['ids'])).all()
    
    # No posts were found
    if (posts == []):
        return {'status': 404, 'msg': 'no posts found', 'body':{}}

    # serialize posts found and return
    body = {'posts': [p.serialize for p in posts]}
    return {'status': 200, 'msg': 'posts found', 'body':body}
    



@blog.route('/post/<id>', methods=['GET'])
def get_post_by_id(id):
    ''' retrieve a blog post from the database '''
    try:
        post = Post.query.filter_by(id=id).first()

        if (not post): 
            raise Exception(f'Could not find post with id {id}')

        response = post.serialize                    
        return {'status': 200, 'msg': 'post found', 'body': post.serialize} 

    except Exception as e:
        return {'status': 404, 'msg': 'post not found', 'body': str(e)} 



######################################################################################################################
######################################################################################################################

@blog.route('/user/<user_id>/posts', methods=['GET'])
def get_posts_by_user (user_id):
    ''' Retrieve all public posts that belongs to a specific user that are not drafts. '''
    posts = Post.query.filter_by(user_id=user_id, private=False, draft=False).all()
    if (posts == None): return {'status': 404, 'msg': 'no posts found', 'body': {}} 
    return {'status': 200, 'msg': 'posts found', 'body': {'posts': [p.serialize for p in posts]}} 



@blog.route('/users/posts', methods=['GET'])
def get_posts_by_users():
    data = request.get_json()
    

    # Get all posts
    if ('ids' not in data):
        return {'status': 409, 'msg': 'require a list of user ids', 'body': {}} 
    
    # Get all posts
    elif (data['ids'] == []):
        return {'status': 409, 'msg': 'no user ids provided in the list', 'body': {}} 

    # Provided ids attribute is not a list
    elif (type(data['ids']) is not list):
        return {'status': 409, 'msg': 'ids must be a list of user ids.', 'body':{}}
    
    # Provided ids attribute is not a list of integers
    for id in data['ids']:
        if (type(id) is not int):
            return {'status': 409, 'msg': 'ids must be a list of user ids represented by integers.', 'body':{}}
    
    posts = Post.query.filter(Post.id.in_(data['ids'])).all()
    
    # No posts were found
    if (posts == []):
        return {'status': 404, 'msg': 'no posts found', 'body':{}}

    # serialize posts found and return
    body = {'posts': [p.serialize for p in posts]}
    return {'status': 200, 'msg': 'posts found', 'body':body}


@blog.route('/user/<user_id>/post/<title>', methods=['GET'])
def get_post_by_user_and_title (user_id, title):
    ''' Retrieve a post that belongs to a specific user. '''
    post = Post.query.filter_by(user_id=user_id, title=title).first()
    if (post == None): return {'status': 404, 'msg': 'post not found', 'body': {}} 
    return {'status': 200, 'msg': 'post found', 'body': {'post': post.serialize}} 

######################################################################################################################
######################################################################################################################


@blog.route('/post/<post_id>/comment/create', methods=['POST'])
@require_token
def create_comment(post_id, user, token):
    ''' Create a new comment for a given post '''
    data = request.get_json()
    data['post_id'] = post_id
    try:
        post = Post.query.filter_by(id=post_id).first()
        if (not post): raise Exception(f'Could not find post with id {post_id}')
        
        comment = Comment.create(data)
        db.session.add(comment)
        db.session.commit()
        return {'status': 200, 'msg':'comment created', 'body': comment.serialize}
    except Exception as e:
        return {'status': 400, 'msg':'comment not created', 'body': str(e)}


@blog.route('/post/<post_id>/comment/<id>', methods=['GET'])
def get_comment(post_id, id):
    ''' Retireve the comment with the matching post_id and id '''
    try:
        comment = Comment.query.filter_by(post_id=post_id, id=id).first()
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
        comment = Comment.query.filter_by(post_id=post_id, id=id).first()
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
        comment = Comment.query.filter_by(post_id=post_id, id=id).first()
        if (not comment): raise Exception(f'Could not find comment with (post_id, id) ({post_id}, {id})')

        db.session.delete(comment)
        db.session.commit()
        return {'status': 200, 'msg':'comment deleted', 'body': {}}
    except Exception as e:
        return {'status': 400, 'msg':'comment not deleted', 'body': str(e)}



######################################################################################################################
######################################################################################################################

@blog.route('/post/<post_id>/comments', methods=['GET'])
def get_comments(post_id):
    ''' return all the comments realted to a post. '''
    try:
        comments = Comment.query.filter_by(post_id=post_id).all()
        return {'status': 200, 'msg':f'{len(comments)} comments found', 'body': [c.serialize for c in comments]}
    except Exception as e:
        return {'status': 400, 'msg':'problem loading comments', 'body': str(e)}





######################################################################################################################
######################################################################################################################
