from config import Config
from flask import Flask
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
fro m flask_restful import Resource, request
from models import *  # noqa: F403

db = SQLAlchemy()
bcrypt = Bcrypt()

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
bcrypt.init_app(app)


class Signup(Resource):
    def post(self):
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return {"message": "Username and password are required."}, 400

        if User.query.filter_by(username=username).first():
            return {"message": "Username already exists."}, 400

        try:
            new_user = User(username=username)
            new_user.password_hash = password
            db.session.add(new_user)
            db.session.commit()
        except ValueError as ve:
            return {"message": str(ve)}, 400

        return user_schema.dump(new_user), 201

app.api.add_resource(Signup, "/signup", endpoint="signup")