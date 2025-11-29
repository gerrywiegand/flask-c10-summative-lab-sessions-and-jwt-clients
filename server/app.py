from config import Config
from flask import Flask, jsonify, make_response, request, 
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    get_jwt_identity,
    verify_jwt_in_request,
)
from flask_restful import Api, Resource
from flask_sqlalchemy import SQLAlchemy
from models import User, user_schema

db = SQLAlchemy()
bcrypt = Bcrypt()

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
bcrypt.init_app(app)
api = Api(app)
jwt = JWTManager(app)

open_routes = ["signup", "login"]


@app.before_request
def check_if_logged_in():
    if request.endpoint not in open_routes:
        verify_jwt_in_request()


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

        return {"Message:User created successfully", user_schema.dump(new_user)}, 201


class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return {"message": "Username and password are required."}, 400

        user = User.query.filter_by(username=username).first()
        if user and user.authenticate(password):
            access_token = create_access_token(identity=user.id)
            return make_response(
                jsonify(token=access_token, user=user_schema.dump(user)), 200
            )
        else:
            return {"message": "Invalid username or password."}, 401


class GetUser(Resource):
    def get(self):
       get_jwt_identity()
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        if not user:
            return {"message": "User not found."}, 404


api.add_resource(Signup, "/signup", endpoint="signup")
api.add_resource(Login, "/login", endpoint="login")
api.add_resource(GetUser, "/me", endpoint="me")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
