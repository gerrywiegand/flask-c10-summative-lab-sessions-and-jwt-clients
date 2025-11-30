from random import choice

from app import app, db
from config import *
from faker import Faker
from flask import Flask
from models import *

fake = Faker()


def create_users():
    users = []
    for _ in range(5):
        username = fake.user_name()
        password = fake.password(
            length=8, special_chars=True, digits=True, upper_case=True
        ) + choice("!@#$%^&*()-_=+[]{}|;:,.<>?/")
        user = User(username=username)
        user.password_hash = password
        db.session.add(user)
        users.append(user)
    db.session.commit()
    return users


def create_notes(users):
    notes = []
    categories = ["Personal", "Work", "Ideas", "Others"]
    for user in users:

        for _ in range(15):
            name = fake.sentence(nb_words=4)[:50]
            content = fake.paragraph(nb_sentences=3)[:500]

            note = Note(
                name=name,
                category=choice(categories),
                content=content,
                user_id=user.id,
            )
            notes.append(note)

    db.session.add_all(notes)
    db.session.commit()


if __name__ == "__main__":
    with app.app_context():
        print("dropping....")
        db.drop_all()
        print("creating....")
        db.create_all()
        print("seeding....")
        print("Creating users...")
        users = create_users()
        print("Creating notes...")
        create_notes(users)
        print("Seeding complete.")
