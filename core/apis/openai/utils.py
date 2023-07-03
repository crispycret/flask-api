
import os

import openai

# openai.File.create(file=open("animals.txt"), purpose="search")

MODELS = [
    'gpt-3.5-turbo',
    'text-davinci-003'
]


def generate_test_prompt(animal):
    return """Suggest three names for an animal that is a superhero.

    Animal: Cat
    Names: Captain Sharpclaw, Agent Fluffball, The Incredible Feline
    Animal: Dog
    Names: Ruff the Protector, Wonder Canine, Sir Barks-a-Lot
    Animal: {}
    Names:""".format(
        animal.capitalize()
    )

def create_completeion(openai_session, model=MODELS[0], prompt=generate_test_prompt('donkey'), temperature=0.6):
    """ Returns a response from the openai API for a completion model. """
    return openai_session.Completion.create(
        model=model,
        prompt=prompt,
        temperature=temperature,
    )
    # result=response.choices[0].text)




DEFAULT_CHAT_MESSAGES = [
    {"role": "system", "content": "You are a helpful assistant."},
    {"role": "user", "content": "Who won the world series in 2020?"},
    {"role": "assistant", "content": "The Los Angeles Dodgers won the World Series in 2020."},
    {"role": "user", "content": "Where was it played?"}
]
 




def create_chat(openai_session, model=MODELS[0], messages=DEFAULT_CHAT_MESSAGES):
    return openai_session.ChatCompletion.create(
        model=model,
        messages=DEFAULT_CHAT_MESSAGES
        
        
    )




