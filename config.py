# config.py

import os

class Config:
    SECRET_KEY = 'roottask'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

class DevelopmentConfig(Config):
    SQLALCHEMY_DATABASE_URI = os.getenv('DEV_DATABASE_URI') or 'mysql+pymysql://admin:hf3h8hews@localhost/tasks_test?charset=utf8mb4'

class ProductionConfig(Config):
    SQLALCHEMY_DATABASE_URI = os.getenv('PROD_DATABASE_URI') or 'mysql+pymysql://admin:hf3h8hews@localhost/tasks'