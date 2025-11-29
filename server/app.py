from config import Config
from flask import Flask
from models import bcrypt, db

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
bcrypt.init_app(app)
