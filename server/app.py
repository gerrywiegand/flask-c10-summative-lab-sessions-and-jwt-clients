from config import Config, bcrypt, db
from flask import Flask, g, jsonify, make_response, request
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    get_jwt_identity,
    verify_jwt_in_request,
)
from flask_restful import Api, Resource
from models import Note, User, note_schema, notes_schema, us
from sqlalchemy import paginate

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
bcrypt.init_app(app)
api = Api(app)
jwt = JWTManager(app)

open_routes = {"signup", "login", "home"}


@app.before_request
def check_if_logged_in():
    # Skip auth for static files or open routes
    if request.endpoint is None:
        return
    if request.endpoint == "static" or request.endpoint in open_routes:
        return

    try:
        verify_jwt_in_request()
        g.current_user_id = int(get_jwt_identity())
    except Exception as e:
        return {"message": str(e)}, 401


class Home(Resource):
    def get(self):
        return {"message": "Welcome to the Note API!"}, 200


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
        user = User.query.get(g.current_user_id)
        if not user:
            return {"message": "User not found."}, 404
        return us.dump(user), 200


class logout(Resource):
    def post(self):
        # Actual logout would be handled front end, simulated here as it is a protected route
        return {"message": "Logout successful."}, 200


class Notes(Resource):
    def get(self, note_id=None):
        if note_id is None:
            notes = Note.query.filter_by(user_id=g.current_user_id).all()
            return notes_schema.dump(notes), 200

        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 10, type=int)

        query = Note.query.filter_by(user_id=g.current_user_id)
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        notes = pagination.items

        response = {
            "notes": notes_schema.dump(notes),
            "page": pagination.page,
            "per_page": pagination.per_page,
            "total": pagination.total,
            "pages": pagination.pages,
        }
        return response, 200

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
            return note_schema.dump(new_note), 201
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
            return note_schema.dump(note), 200
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
api.add_resource(logout, "/logout", endpoint="logout")
api.add_resource(GetUser, "/me", endpoint="me")
api.add_resource(Notes, "/notes", "/notes/<int:note_id>", endpoint="notes")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
