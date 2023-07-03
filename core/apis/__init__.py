from flask import Blueprint


apis = Blueprint('apis', __name__, url_prefix='/apis')

from . import openai

