from flask import Blueprint

blog = Blueprint('blog', __name__, '/<username>/blog')


from . import views
from . import models