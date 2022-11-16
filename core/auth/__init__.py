

from flask import Blueprint

auth = Blueprint('auth', __name__, url_prefix='/auth')

from . import utils
from . import models
from . import routes
from . import decorators
