# Full Auth Flask Backend — Productivity Tool API

A secure Flask REST API implementing JWT authentication, user management, and full CRUD for a Notes resource with pagination and ownership protection.

---

## 🚀 Features

- JWT-based authentication (signup, login, logout)
- Password hashing with bcrypt
- User can only access or modify their notes
- Full CRUD for notes
- Pagination on GET /notes
- Data validation with Marshmallow
- Database seeding for demo/testing
- Flask-Migrate enabled

---

## 🔧 Tech Stack

- Python 3.11+
- Flask, Flask-RESTful
- Flask-JWT-Extended
- Flask-SQLAlchemy
- Flask-Migrate
- Flask-Bcrypt
- Marshmallow
- SQLite
- Faker (seed data)

---

## 📦 Installation

```bash
git clone <your-repo-url>
cd <project-folder>
pipenv install
pipenv shell
```

---

## Database setup

```bash
flask db init        # first time only
flask db migrate -m "initial"
flask db upgrade
```

## Seed Data

python seed.py

This will create a test user with a username of "Test" and password of "Test1!"
along with multipe fake users and 15 notes per user

## Run The server

```bash
flask run
```

or

```bash
python app.py
```

server will run at http://127.0.0.1:5000

## Authentication

an example of the process

# Signup - POST/signup

{ "username": "john", "password": "John123!" } # or your user/ test user

# Login — POST /login

Returns JWT:

{ "token": "<jwt>", "user": { ... } }

_Auth header (required for all /notes routes)_
Authorization: Bearer <token>

## Endpoints

| Method | Endpoint    | Description                    |
| ------ | ----------- | ------------------------------ |
| GET    | /notes      | Paginated list of user's notes |
| GET    | /notes/<id> | View one note (owned only)     |
| POST   | /notes      | Create new note                |
| PATCH  | /notes/<id> | Update note                    |
| DELETE | /notes/<id> | Delete note                    |

## Testing (Postman)

Login → copy JWT

Add header:
Authorization: Bearer <token>

Test all CRUD routes and pagination
