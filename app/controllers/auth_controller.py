import logging
import jwt
import datetime
from flask import jsonify, current_app as app
from app import db
from app.models.user_model import User
from werkzeug.security import generate_password_hash, check_password_hash


def register_user(data):
    username = data.get("username")
    password = data.get("password")
    name = data.get("name")
    family = data.get("family")
    email = data.get("email")

    if not username or not password:
        return {"error": "Username and password are required"}, 400

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return {"error": "Username already exists"}, 409

    hashed_password = generate_password_hash(password)

    new_user = User(username=username, password=hashed_password, name=name, family=family, email=email)

    db.session.add(new_user)
    db.session.commit()

    return {"message": "User registered successfully"}, 201


def login_user(data):
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        logging.warning("Login attempt with missing username or password.")
        return {"error": "Username and password are required"}, 400

    user = User.query.filter_by(username=username).first()

    if not user or not check_password_hash(user.password, password):
        logging.warning(f"Failed login attempt for username: {username}")
        return {"error": "Invalid username or password"}, 401

    expiration_minutes = app.config['JWT_EXPIRATION_DELTA']
    expiration_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=expiration_minutes)

    token = jwt.encode({
        "user_id": user.id,
        "exp": expiration_time
    }, app.config['SECRET_KEY'], algorithm="HS256")

    logging.info(f"User {username} logged in successfully.")
    return {"message": "Login successful", "token": token}, 200
