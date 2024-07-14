import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    SECRET_KEY = 'roottask'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

class DevelopmentConfig(Config):
    SQLALCHEMY_DATABASE_URI = os.getenv('DEV_DATABASE_URI')

class ProductionConfig(Config):
    SQLALCHEMY_DATABASE_URI = os.getenv('PROD_DATABASE_URI')

class NLUConfig(Config):
    SQLALCHEMY_DATABASE_URI = os.getenv('NLU_DATABASE_URI')

class CalConfig(Config):
    SQLALCHEMY_DATABASE_URI = os.getenv('CAL_DATABASE_URI')
