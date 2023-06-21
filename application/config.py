import os
basedir = os.path.abspath(os.path.dirname(__file__))
dir = os.path.dirname(basedir)

class Config():
    SQLITE_DB_DIR = os.path.join(basedir,"../db_directory")
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(SQLITE_DB_DIR,"Database.sqlite3")
    UPLOAD_FOLDER = os.path.join(basedir,'../uploads')
    MAIL_SERVER='smtp.gmail.com'
    SECRET_KEY = '\x1d\x02p\xf6\x8e,\xa7G\xa5\xeaF\xe9\xb4|\x9d\x87\x9d\xbe\xcc:\x18M\xbb]'
    MAIL_PORT= 465
    MAIL_USERNAME = 'testsender135@gmail.com'
    MAIL_PASSWORD = 'Password@135'
    MAIL_USE_TLS = False
    MAIL_USE_SSL = True
    DEBUG = True 