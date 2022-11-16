from flask import Blueprint


social = Blueprint('social', __name__, url_prefix='/social')

from . import routes
from . import models