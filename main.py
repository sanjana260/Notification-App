from flask import Flask 
from application.config import Config
from application.database import db

app = Flask(__name__)

app.config.from_object(Config)
db.init_app(app)
app.app_context().push()
from application.controllers import *

if __name__=='__main__':
    db.create_all()
    app.run(host = '0.0.0.0',port = 8000)
    