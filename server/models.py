from datetime import UTC, datetime, timezone

from config import bcrypt, db
from marshmallow import Schema, fields
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import validates


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True, nullable=False)
    _password_hash = db.Column(db.String(128), nullable=False)

    @hybrid_property
    def password_hash(self):
        raise AttributeError("Password hashes may not be viewed.")

    @password_hash.setter
    def password_hash(self, password):
        # Validate password format before hashing
        required_special_chars = "!@#$%^&*()-_=+[]{}|;:,.<>?/"
        required_alpha = any(c.isalpha() for c in password)
        required_digit = any(c.isdigit() for c in password)
        required_special = any(c in required_special_chars for c in password)

        if not password or len(password) < 6:
            raise ValueError("Password must be at least 6 characters long.")
        if len(password) > 128:
            raise ValueError("Password cannot exceed 128 characters.")
        if not (required_alpha and required_digit and required_special):
            raise ValueError(
                "Password must contain a letter, number, and special character."
            )

        # Hash and store the password
        self._password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password)

    @validates("username")
    def validate_username(self, key, username):
        if not username or len(username) < 3 or len(username) > 15:
            raise ValueError("Username must be between 3 and 15 characters long.")
        return username

    def __repr__(self):
        return f"<User {self.username}>"

    notes = db.relationship("Note", back_populates="user", cascade="all, delete-orphan")


class UserSchema(Schema):
    id = fields.Int(dump_only=True)
    username = fields.Str()
    password_hash = fields.Str(load_only=True)


us = UserSchema()


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(
        db.String(50),
        nullable=False,
    )
    category = db.Column(db.String(50), nullable=True)
    content = db.Column(db.String(500), nullable=False)
    date_created = db.Column(
        db.DateTime,
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    user = db.relationship("User", back_populates="notes")

    def __repr__(self):
        return (
            f"<Notes {self.id},{self.name},{self.date_created} {self.content[:20]}...>"
        )

    @validates("name")
    def validate_name(self, key, name):
        if not name or len(name) < 1 or len(name) > 50:
            raise ValueError("Name must be between 1 and 50 characters long.")
        return name

    @validates("content")
    def validate_content(self, key, content):
        if not content or len(content) < 1 or len(content) > 500:
            raise ValueError("Content must be between 1 and 500 characters long.")
        return content

    @validates("category")
    def validate_category(self, key, category):
        if category and (len(category) < 1 or len(category) > 50):
            raise ValueError("Category must be between 1 and 50 characters long.")
        return category

    @validates("user_id")
    def validate_user_id(self, key, user_id):
        if not user_id:
            raise ValueError("user_id is required.")
        return user_id


class NotesSchema(Schema):
    id = fields.Int(dump_only=True)
    name = fields.Str()
    category = fields.Str()
    content = fields.Str()
    date_created = fields.DateTime()
    user_id = fields.Int(dump_only=True)


note_schema = NotesSchema()
notes_schema = NotesSchema(many=True)
