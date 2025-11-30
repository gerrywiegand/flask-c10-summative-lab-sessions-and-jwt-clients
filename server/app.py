from config import *
from flask import Flask, g, jsonify, make_response, request
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    get_jwt_identity,
    verify_jwt_in_request,
)
from flask_restful import Api, Resource
from models import Note, NoteSchema, User, us

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
bcrypt.init_app(app)
api = Api(app)
jwt = JWTManager(app)

open_routes = ["signup", "login", "home", "static"]


@app.before_request
def check_if_logged_in():
    if request.endpoint in ("static", None, open_routes):
        return
    try:
        verify_jwt_in_request()
        user_id = int(get_jwt_identity())
        g.current_user_id = user_id
    except Exception as e:
        return {"message": str(e)}, 401


class Home(Resource):
    def get(self):
        return {"message": "Welcome to the Notes API!"}, 200


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

        return {
            "Message": "User created successfully",
            "User": us.dump(new_user),
        }, 201


class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return {"message": "Username and password are required."}, 400

        user = User.query.filter_by(username=username).first()
        if user and user.authenticate(password):
            access_token = create_access_token(identity=str(user.id))
            return make_response(jsonify(token=access_token, user=us.dump(user)), 200)
        else:
            return {"message": "Invalid username or password."}, 401


class GetUser(Resource):
    def get(self):
        user_id = int(get_jwt_identity())
        user = User.query.get(user_id)
        if not user:
            return {"message": "User not found."}, 404
        return us.dump(user), 200


class Notes(Resource):
    def get_all(self):
        notes = Note.query.filter_by(user_id=g.current_user_id).all()
        return NoteSchema.dump(notes, many=True), 200

    def get_by_id(self, note_id):
        note = Note.query.filter_by(id=note_id, user_id=g.current_user_id).first()

        if not note:
            return {"message": "Note not found."}, 404

        return NoteSchema.dump(note), 200

    def post(self):
        data = request.get_json()
        try:
            new_note = Note(
                name=data.get("name"),
                category=data.get("category"),
                content=data.get("content"),
                user_id=g.current_user_id,
            )
            db.session.add(new_note)
            db.session.commit()
            return NoteSchema.dump(new_note), 201
        except ValueError as ve:
            return {"message": str(ve)}, 400

    def patch(self, note_id):
        note = Note.query.filter_by(id=note_id, user_id=g.current_user_id).first()
        if not note:
            return {"message": "Note not found."}, 404

        data = request.get_json()
        try:
            if "name" in data:
                note.name = data["name"]
            if "category" in data:
                note.category = data["category"]
            if "content" in data:
                note.content = data["content"]

            db.session.commit()
            return NoteSchema.dump(note), 200
        except ValueError as ve:
            return {"message": str(ve)}, 400

    def delete(self, note_id):
        note = Note.query.filter_by(id=note_id, user_id=g.current_user_id).first()
        if not note:
            return {"message": "Note not found."}, 404
        db.session.delete(note)
        db.session.commit()
        return {"message": "Note deleted successfully."}, 200


api.add_resource(Home, "/", endpoint="home")
api.add_resource(Signup, "/signup", endpoint="signup")
api.add_resource(Login, "/login", endpoint="login")
api.add_resource(GetUser, "/me", endpoint="me")
api.add_resource(
    Notes,
    "/notes",
    "/notes/<int:note_id>",
    endpoint="notes",
    resource_class_kwargs={
        "get_all": Notes.get_all,
        "get_by_id": Notes.get_by_id,
        "post": Notes.post,
        "patch": Notes.patch,
        "delete": Notes.delete,
    },
)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
