import logging
import jwt
import re
import bleach
import random
import datetime
from flask import jsonify, current_app as app
from app import db
from app.models.user_model import User
from werkzeug.security import generate_password_hash, check_password_hash
from app.helpers.email_helpers import send_email


def register_controller(data):
    mobile = bleach.clean(data.get("mobile", "").strip())
    password = bleach.clean(data.get("password", "").strip())
    name = bleach.clean(data.get("name", "").strip())

    logging.info(f"Registration attempt for mobile: {mobile}")

    if not mobile or not password or not name:
        logging.warning("Registration failed: Missing required feilds.")
        return {"error": "Missing required feilds."}, 400

    if not re.match(r'^09\d{9}$', mobile):
        logging.warning(f"Registration failed: Invalid mobile number format for {mobile}.")
        return {"error": "Invalid mobile number format. It should start with '09' and contain 11 digits."}, 400

    if not (8 <= len(password) <= 16):
        logging.warning("Registration failed: Password length is invalid.")
        return {"error": "Password must be between 8 and 16 characters long."}, 400

    if not re.match(r'^[a-zA-Z\u0600-\u06FF\s]+$', name):
        logging.warning(f"Registration failed: Invalid name format for {name}.")
        return {"error": "Name must contain only Persian or English letters."}, 400
    
    existing_user_mobile = User.query.filter_by(mobile=mobile).first()
    if existing_user_mobile:
        logging.warning(f"Registration failed: Mobile number {mobile} already exists.")
        return {"error": "Mobile number already exists"}, 409

    verify_code = random.randint(111111, 999999)
    logging.info(f"Generated verify_code {verify_code} for mobile {mobile}.")
    
    hashed_password = generate_password_hash(password)

    new_user = User(mobile=mobile, password=hashed_password, name=name, verify_code=verify_code)

    try:
        db.session.add(new_user)
        db.session.commit()
        logging.info(f"User {mobile} registered successfully.")
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to register user {mobile}: {e}")
        return {"error": "An error occurred during registration"}, 500

    return {"message": "User registered successfully"}, 201


def login_controller(data):
    mobile = data.get("mobile")
    password = data.get("password")

    if not mobile or not password:
        logging.warning("Login attempt with missing mobile or password.")
        return {"error": "mobile and password are required"}, 400

    user = User.query.filter_by(mobile=mobile).first()

    if not user or not check_password_hash(user.password, password):
        logging.warning(f"Failed login attempt for mobile: {mobile}")
        return {"error": "Invalid mobile or password"}, 401

    expiration_minutes = app.config['JWT_EXPIRATION_DELTA']
    expiration_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=expiration_minutes)

    token = jwt.encode({
        "user_id": user.id,
        "exp": expiration_time
    }, app.config['SECRET_KEY'], algorithm="HS256")


    # send_email(
    #     subject="Welcome to Our Platform!",
    #     recipients=["rezashataie75@gmail.com"],
    #     template_name="welcome.html",
    #     template_data={
    #         "username": "John Doe",
    #         "platform_name": "MyApp"
    #     }
    # )
    
    # send_email(
    #     subject="Password Reset Request",
    #     recipients=["rezashataie75@gmail.com"],
    #     template_name="reset-password.html",
    #     template_data={
    #         "username": "John Doe",
    #         "reset_link": "https://example.com/reset-password?token=abc123"
    #     }
    # )

    logging.info(f"User {mobile} logged in successfully.")
    return {"message": "Login successful", "token": token}, 200


def change_password_controller(data, user_id):
    # Parse data
    current_password = data.get("current_password")
    new_password = data.get("new_password")

    if not current_password or not new_password:
        logging.warning("Password change failed: Missing current or new password.")
        return {"error": "Current password and new password are required"}, 400

    # Fetch user from the database
    user = User.query.get(user_id)
    if not user:
        logging.warning(f"Password change failed: User ID {user_id} not found.")
        return {"error": "User not found"}, 404

    # Validate current password
    if not check_password_hash(user.password, current_password):
        logging.warning(f"Password change failed: Incorrect current password for user ID {user_id}.")
        return {"error": "Current password is incorrect"}, 401

    # Validate new password length
    if not (8 <= len(new_password) <= 16):
        logging.warning(f"Password change failed: Invalid new password length for user ID {user_id}.")
        return {"error": "Password must be between 8 and 16 characters long."}, 400

    # Update password
    user.password = generate_password_hash(new_password)
    try:
        db.session.commit()
        logging.info(f"Password changed successfully for user ID {user_id}.")
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to change password for user ID {user_id}: {e}")
        return {"error": "An error occurred while updating the password"}, 500

    return {"message": "Password updated successfully"}, 200
