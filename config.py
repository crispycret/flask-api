import os

from dotenv import load_dotenv
load_dotenv()

basedir = os.path.abspath(os.path.dirname(__file__))

_summary_ = """
    The Configuration class is used to configure and secure the application.
    
    SECRET_KEY - Application secret key that needs to be generated by the application developer.
                 This parameter is used to sign and read authentication requests.
        [+] Build a tool to help the application developer create and manage SECRET_KEY generation. 
     
"""

__SQLALCHEMY_DATABASE_URI__ = os.getenv("DATABASE_URI") or \
    'sqlite:///' + os.path.join(basedir, 'default.db')

if __SQLALCHEMY_DATABASE_URI__.startswith("postgres://"):
    __SQLALCHEMY_DATABASE_URI__ = __SQLALCHEMY_DATABASE_URI__.replace("postgres://", "postgresql://", 1)

class Configuration (object):
    SECRET_KEY = os.environ.get('SECRET_KEY')
    ADMIN_SECRET_KEY = os.environ.get('ADMIN_SECRET_KEY')

    SQLALCHEMY_DATABASE_URI = __SQLALCHEMY_DATABASE_URI__
    SQLALCHEMY_TRACK_MODIFICATIONS = True

    
    