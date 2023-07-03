from flask import session, request
import openai 
from . import openai as app
from . import utils


# Decorator require_api_key

@app.route('/prompt', methods=['POST'])
def prompt():
    api_key = session.get('OPENAI_API_KEY')
    if not api_key: return

    # Set the
    import openai
    openai.api_key = api_key
    utils.create_completeion(openai)
    
    

@app.route('/chat')
def chat(): pass



@app.route('/dalle')
def dalle_create(): pass