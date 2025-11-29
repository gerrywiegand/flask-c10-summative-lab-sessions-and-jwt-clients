from config import Config
from flask import Flask
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
bcrypt = Bcrypt()

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
bcrypt.init_app(app)
