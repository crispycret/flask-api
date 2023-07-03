from flask import Blueprint

openai = Blueprint('openai', __name__, url_prefix='/openai')


from . import routes
from . import utils
from . import models