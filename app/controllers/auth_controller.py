import logging
import jwt
import re
import bleach
import random
import datetime
from flask import current_app as app
from app import db
from app.models.user_model import User
from werkzeug.security import generate_password_hash, check_password_hash
from app.helpers.email_helpers import send_email


def register_controller(data):
    mobile = bleach.clean(data.get("mobile", "").strip())
    email = bleach.clean(data.get("email", "").strip().lower())
    password = bleach.clean(data.get("password", "").strip())
    name = bleach.clean(data.get("name", "").strip())

    logging.info(f"Registration attempt for mobile: {mobile}")

    if not mobile or not password or not name or not email:
        logging.warning("Registration failed: Missing required feilds.")
        return {"error": "Missing required feilds."}, 400

    if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
        logging.warning(f"Registration failed: Invalid email format for {email}.")
        return {"error": "Invalid email format."}, 400

    if not re.match(r"^09\d{9}$", mobile):
        logging.warning(
            f"Registration failed: Invalid mobile number format for {mobile}."
        )
        return {
            "error": "Invalid mobile number format. It should start with '09' and contain 11 digits."
        }, 400

    if not (8 <= len(password) <= 16):
        logging.warning("Registration failed: Password length is invalid.")
        return {"error": "Password must be between 8 and 16 characters long."}, 400

    if not re.match(r"^[a-zA-Z0-9\-_!@#$%?]+$", password):
        logging.warning(f"Registration failed: Invalid password format.")
        return {
            "error": "Password can only contain letters, numbers, and the following characters: - _ ! @ # $ % ?"
        }, 400

    if not re.match(r"^[a-zA-Z\u0600-\u06FF\s]+$", name):
        logging.warning(f"Registration failed: Invalid name format for {name}.")
        return {"error": "Name must contain only Persian or English letters."}, 400

    existing_user_mobile = User.query.filter_by(mobile=mobile).first()
    if existing_user_mobile:
        logging.warning(f"Registration failed: Mobile number {mobile} already exists.")
        return {"error": "Mobile number already exists"}, 409

    existing_user_email = User.query.filter_by(email=email).first()
    if existing_user_email:
        logging.warning(f"Registration failed: Email {email} already exists.")
        return {"error": "Email already exists"}, 409

    verify_code = random.randint(111111, 999999)
    logging.info(f"Generated verify_code {verify_code} for mobile {mobile}.")

    hashed_password = generate_password_hash(password)

    new_user = User(
        mobile=mobile,
        email=email,
        password=hashed_password,
        name=name,
        verify_code=verify_code,
    )

    try:
        db.session.add(new_user)
        db.session.commit()
        logging.info(f"User {mobile} registered successfully.")
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to register user {mobile}: {e}")
        return {"error": "An error occurred during registration"}, 500

    send_email(
        subject="Welcome to Pan2mim!",
        recipients=[email],
        template_name="register",
        template_data={"name": name, "code": verify_code},
    )

    return {"message": "User registered successfully"}, 201


def active_user_controller(data):
    mobile = bleach.clean(data.get("mobile", "").strip())
    otp = bleach.clean(data.get("otp", "").strip())

    logging.info(f"Activation attempt for mobile: {mobile} with OTP: {otp}")

    if not mobile or not otp:
        logging.warning("Activation failed: Missing required fields.")
        return {"error": "Missing required fields."}, 400

    if not re.match(r"^09\d{9}$", mobile):
        logging.warning(
            f"Activation failed: Invalid mobile number format for {mobile}."
        )
        return {
            "error": "Invalid mobile number format. It should start with '09' and contain 11 digits."
        }, 400

    if not re.match(r"^\d{6}$", otp):
        logging.warning(f"Activation failed: Invalid OTP format for {otp}.")
        return {"error": "Invalid OTP format. It should be a 6-digit number."}, 400

    user = User.query.filter_by(mobile=mobile).first()
    if not user:
        logging.warning(f"Activation failed: No user found with mobile {mobile}.")
        return {"error": "User not found."}, 404

    if str(user.verify_code) != otp:
        try:
            user.verify_try += 1
            logging.warning(
                f"Incorrect OTP for mobile {mobile}. Attempt {user.verify_try}/3."
            )

            if user.verify_try > 5:
                db.session.delete(user)
                db.session.commit()
                logging.warning(f"User {mobile} deleted after 3 failed OTP attempts.")
                return {
                    "error": "Too many incorrect attempts. User has been deleted."
                }, 403

            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logging.error(f"Failed to update verify_try for user {mobile}: {e}")
            return {"error": "An error occurred while processing your request."}, 500

        return {"error": "Invalid OTP. Please try again."}, 401

    try:
        user.status = "active"
        user.verify_try = 0
        db.session.commit()
        logging.info(f"User {mobile} activated successfully.")
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to activate user {mobile}: {e}")
        return {"error": "An error occurred during activation."}, 500

    return {"message": "User activated successfully."}, 200


def login_controller(data):
    email = bleach.clean(data.get("email", "").strip().lower())
    password = bleach.clean(data.get("password", "").strip())

    if not email or not password:
        logging.warning("Login attempt with missing email or password.")
        return {"error": "email and password are required"}, 400

    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password, password):
        logging.warning(f"Failed login attempt for email: {email}")
        return {"error": "Invalid email or password"}, 401

    expiration_minutes = app.config["JWT_EXPIRATION_DELTA"]
    expiration_time = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        minutes=expiration_minutes
    )

    token = jwt.encode(
        {"user_id": user.id, "name": user.name, "exp": expiration_time},
        app.config["SECRET_KEY"],
        algorithm="HS256",
    )

    logging.info(f"User {email} logged in successfully.")
    return {"message": "Login successful", "token": token}, 200


def change_password_controller(data, user_id):
    current_password = bleach.clean(data.get("current_password", "").strip())
    new_password = bleach.clean(data.get("new_password", "").strip())

    if not current_password or not new_password:
        logging.warning("Password change failed: Missing current or new password.")
        return {"error": "Current password and new password are required"}, 400

    user = User.query.get(user_id)
    if not user:
        logging.warning(f"Password change failed: User ID {user_id} not found.")
        return {"error": "User not found"}, 404

    if not check_password_hash(user.password, current_password):
        logging.warning(
            f"Password change failed: Incorrect current password for user ID {user_id}."
        )
        return {"error": "Current password is incorrect"}, 401

    if not (8 <= len(new_password) <= 16):
        logging.warning(
            f"Password change failed: Invalid new password length for user ID {user_id}."
        )
        return {"error": "Password must be between 8 and 16 characters long."}, 400

    if not re.match(r"^[a-zA-Z0-9\-_!@#$%?]+$", new_password):
        logging.warning(f"Registration failed: Invalid password format.")
        return {
            "error": "Password can only contain letters, numbers, and the following characters: - _ ! @ # $ % ?"
        }, 400

    user.password = generate_password_hash(new_password)
    try:
        db.session.commit()
        logging.info(f"Password changed successfully for user ID {user_id}.")
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to change password for user ID {user_id}: {e}")
        return {"error": "An error occurred while updating the password"}, 500

    return {"message": "Password updated successfully"}, 200


# def forgot_password_controller(data, user_id):
