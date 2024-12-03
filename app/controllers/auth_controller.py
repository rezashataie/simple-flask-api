# app/controllers/auth_controller.py

import logging
import bleach
import random
import re
from werkzeug.security import generate_password_hash, check_password_hash
from app.models.user_model import User
from app.helpers.email_helpers import EmailService
from email_validator import validate_email, EmailNotValidError
import phonenumbers
from phonenumbers.phonenumberutil import NumberParseException
from password_strength import PasswordPolicy
from sqlalchemy.exc import SQLAlchemyError
from app.helpers.db_helpers import session_scope
from flask_jwt_extended import create_access_token


class AuthController:
    """
    This class handles all authentication-related actions including
    registration, activation, login, password change, and reset operations.
    """

    def __init__(self):
        self.email_service = EmailService()  # Initialize the email service
        # Define password policy
        self.password_policy = PasswordPolicy.from_names(
            length=8,  # Minimum length: 8
            uppercase=1,  # At least one uppercase letter
            numbers=1,  # At least one digit
            special=1,  # At least one special character
            nonletters=0,  # No requirement for non-letter characters
        )

    def register(self, data):
        """
        Register a new user.
        :param data: Dictionary containing mobile, email, password, and name.
        """
        mobile = bleach.clean(data.get("mobile", "").strip())
        email = bleach.clean(data.get("email", "").strip().lower())
        password = bleach.clean(data.get("password", "").strip())
        name = bleach.clean(data.get("name", "").strip())

        logging.info(
            f"Registration attempt for mobile: {self.anonymize_mobile(mobile)}"
        )

        # Validate inputs
        if not mobile or not password or not name or not email:
            logging.warning("Registration failed: Missing required fields.")
            return {"error": "Missing required fields."}, 400

        # Validate email
        try:
            valid_email = validate_email(email)
            email = valid_email.email  # Normalized email
        except EmailNotValidError:
            logging.warning(
                f"Registration failed: Invalid email format for {self.anonymize_email(email)}."
            )
            return {"error": "Invalid email format."}, 400

        # Validate mobile number
        try:
            phone_number = phonenumbers.parse(mobile, "IR")
            if not phonenumbers.is_valid_number(phone_number):
                raise ValueError("Invalid phone number")
            mobile = phonenumbers.format_number(
                phone_number, phonenumbers.PhoneNumberFormat.E164
            )
        except (NumberParseException, ValueError):
            logging.warning(
                f"Registration failed: Invalid mobile number format for {self.anonymize_mobile(mobile)}."
            )
            return {"error": "Invalid mobile number format."}, 400

        # Validate password according to policy
        password_errors = self.password_policy.test(password)
        if password_errors:
            logging.warning(
                "Registration failed: Password does not meet policy requirements."
            )
            return {
                "error": "Password must be at least 8 characters long and include uppercase letters, numbers, and special characters."
            }, 400

        # Validate name (only Persian or English letters and spaces)
        if not re.match(r"^[a-zA-Z\u0600-\u06FF\s]+$", name):
            logging.warning(f"Registration failed: Invalid name format for {name}.")
            return {"error": "Name must contain only Persian or English letters."}, 400

        # Check for existing user with the same email or mobile
        with session_scope() as session:
            if session.query(User).filter_by(mobile=mobile).first():
                logging.warning(
                    f"Registration failed: Mobile number {self.anonymize_mobile(mobile)} already exists."
                )
                return {"error": "Mobile number already exists"}, 409

            if session.query(User).filter_by(email=email).first():
                logging.warning(
                    f"Registration failed: Email {self.anonymize_email(email)} already exists."
                )
                return {"error": "Email already exists"}, 409

            # Generate verification code
            verify_code = random.randint(111111, 999999)
            logging.info(
                f"Generated verify_code for mobile {self.anonymize_mobile(mobile)}."
            )

            hashed_password = generate_password_hash(password)

            # Create a new user
            new_user = User(
                mobile=mobile,
                email=email,
                password=hashed_password,
                name=name,
                verify_code=verify_code,
            )
            session.add(new_user)

        logging.info(f"User {self.anonymize_mobile(mobile)} registered successfully.")

        # Send verification email
        self.email_service.send(
            subject="Welcome to Pan2mim!",
            recipients=[email],
            template_name="register",
            template_data={"name": name, "code": verify_code},
        )

        return {"message": "User registered successfully"}, 201

    def activate_user(self, data):
        """
        Activate a user using email and verification code.
        :param data: Dictionary containing email and otp.
        """
        email = bleach.clean(data.get("email", "").strip().lower())
        otp = bleach.clean(data.get("otp", "").strip())

        logging.info(f"Activation attempt for email: {self.anonymize_email(email)}")

        # Validate inputs
        if not email or not otp:
            logging.warning("Activation failed: Missing required fields.")
            return {"error": "Missing required fields."}, 400

        # Validate email
        try:
            valid_email = validate_email(email)
            email = valid_email.email  # Normalized email
        except EmailNotValidError:
            logging.warning(
                f"Activation failed: Invalid email format for {self.anonymize_email(email)}."
            )
            return {"error": "Invalid email format."}, 400

        # Validate OTP code
        if not re.match(r"^\d{6}$", otp):
            logging.warning("Activation failed: Invalid OTP format.")
            return {"error": "Invalid OTP format. It should be a 6-digit number."}, 400

        try:
            with session_scope() as session:
                user = (
                    session.query(User)
                    .filter_by(email=email, status="inactive")
                    .first()
                )
                if not user:
                    logging.warning(
                        f"Activation failed: No user found with email {self.anonymize_email(email)}."
                    )
                    return {"error": "User not found."}, 404

                # Verify OTP code
                if str(user.verify_code) != otp:
                    user.verify_try += 1
                    if user.verify_try > 5:
                        session.delete(user)
                        logging.warning(
                            f"User {self.anonymize_email(email)} deleted after 5 failed OTP attempts."
                        )
                        return {
                            "error": "Too many incorrect attempts. User has been deleted."
                        }, 403
                    logging.warning(
                        f"Incorrect OTP for email {self.anonymize_email(email)}. Attempt {user.verify_try}/5."
                    )
                    return {"error": "Invalid OTP. Please try again."}, 401

                # Activate user
                user.status = "active"
                user.verify_try = 0
                user.verify_code = None
                logging.info(
                    f"User {self.anonymize_email(email)} activated successfully."
                )
        except SQLAlchemyError as e:
            logging.error(f"Failed to activate user {self.anonymize_email(email)}: {e}")
            return {"error": "An error occurred during activation."}, 500

        return {"message": "User activated successfully."}, 200

    def login(self, data):
        """
        Log in a user using email and password.
        :param data: Dictionary containing email and password.
        """
        email = bleach.clean(data.get("email", "").strip().lower())
        password = bleach.clean(data.get("password", "").strip())

        if not email or not password:
            logging.warning("Login attempt with missing email or password.")
            return {"error": "Email and password are required"}, 400

        # Validate email
        try:
            valid_email = validate_email(email)
            email = valid_email.email  # Normalized email
        except EmailNotValidError:
            logging.warning(
                f"Login failed: Invalid email format for {self.anonymize_email(email)}."
            )
            return {"error": "Invalid email or password"}, 401

        try:
            with session_scope() as session:
                user = session.query(User).filter_by(email=email).first()
                if not user or not check_password_hash(user.password, password):
                    logging.warning(
                        f"Failed login attempt for email: {self.anonymize_email(email)}"
                    )
                    return {"error": "Invalid email or password"}, 401

                # Generate JWT token
                additional_claims = {"name": user.name}
                access_token = create_access_token(
                    identity=user.id, additional_claims=additional_claims
                )
                logging.info(
                    f"User {self.anonymize_email(email)} logged in successfully."
                )
                return {"message": "Login successful", "token": access_token}, 200
        except SQLAlchemyError as e:
            logging.error(f"Failed to log in user {self.anonymize_email(email)}: {e}")
            return {"error": "An error occurred during login"}, 500

    def change_password(self, data, user_id):
        """
        Change the password for a logged-in user.
        :param data: Dictionary containing current_password and new_password.
        :param user_id: ID of the logged-in user from the JWT token.
        """
        current_password = bleach.clean(data.get("current_password", "").strip())
        new_password = bleach.clean(data.get("new_password", "").strip())

        # Validate inputs
        if not current_password or not new_password:
            logging.warning("Password change failed: Missing current or new password.")
            return {"error": "Current password and new password are required"}, 400

        try:
            with session_scope() as session:
                user = session.query(User).get(user_id)
                if not user:
                    logging.warning(
                        f"Password change failed: User ID {user_id} not found."
                    )
                    return {"error": "User not found"}, 404

                # Verify current password
                if not check_password_hash(user.password, current_password):
                    logging.warning(
                        f"Password change failed: Incorrect current password for user ID {user_id}."
                    )
                    return {"error": "Current password is incorrect"}, 401

                # Validate new password
                password_errors = self.password_policy.test(new_password)
                if password_errors:
                    logging.warning(
                        "Password change failed: New password does not meet policy requirements."
                    )
                    return {
                        "error": "New password must be at least 8 characters long and include uppercase letters, numbers, and special characters."
                    }, 400

                # Update password
                user.password = generate_password_hash(new_password)
                logging.info(f"Password changed successfully for user ID {user_id}.")
        except SQLAlchemyError as e:
            logging.error(f"Failed to change password for user ID {user_id}: {e}")
            return {"error": "An error occurred while updating the password"}, 500

        return {"message": "Password updated successfully"}, 200

    def reset_password_request(self, data):
        """
        Request a password reset by sending a reset code to the user's email.
        :param data: Dictionary containing email.
        """
        email = bleach.clean(data.get("email", "").strip().lower())

        if not email:
            logging.warning("Password reset failed: Missing email.")
            return {"error": "Email is required."}, 400

        # Validate email
        try:
            valid_email = validate_email(email)
            email = valid_email.email  # Normalized email
        except EmailNotValidError:
            logging.warning(
                f"Password reset failed: Invalid email format for {self.anonymize_email(email)}."
            )
            return {"error": "Invalid email format."}, 400

        try:
            with session_scope() as session:
                user = session.query(User).filter_by(email=email).first()
                if not user:
                    logging.warning(
                        f"Password reset: User not found for {self.anonymize_email(email)}"
                    )
                    return {"error": "Invalid email"}, 404

                # Generate reset code
                reset_code = random.randint(111111, 999999)
                user.reset_code = reset_code
                user.reset_try = 0
                logging.info(
                    f"Reset code saved successfully for user {self.anonymize_email(email)}"
                )
        except SQLAlchemyError as e:
            logging.error(
                f"Failed to save reset code for user {self.anonymize_email(email)}: {e}"
            )
            return {"error": "An error occurred during password reset request."}, 500

        # Send reset code via email
        self.email_service.send(
            subject="Reset your password!",
            recipients=[email],
            template_name="reset-password",
            template_data={"name": user.name, "code": reset_code},
        )

        return {"message": "Reset code sent successfully"}, 201

    def reset_password_update(self, data):
        """
        Update the password after verifying the reset code.
        :param data: Dictionary containing email, otp, and new_password.
        """
        email = bleach.clean(data.get("email", "").strip().lower())
        otp = bleach.clean(data.get("otp", "").strip())
        new_password = bleach.clean(data.get("new_password", "").strip())

        # Validate inputs
        if not email or not otp or not new_password:
            logging.warning("Password reset update failed: Missing required fields.")
            return {"error": "Missing required fields."}, 400

        # Validate email
        try:
            valid_email = validate_email(email)
            email = valid_email.email  # Normalized email
        except EmailNotValidError:
            logging.warning(
                f"Password reset update failed: Invalid email format for {self.anonymize_email(email)}."
            )
            return {"error": "Invalid email format."}, 400

        # Validate OTP code
        if not re.match(r"^\d{6}$", otp):
            logging.warning("Password reset update failed: Invalid OTP format.")
            return {"error": "Invalid OTP format. It should be a 6-digit number."}, 400

        try:
            with session_scope() as session:
                user = (
                    session.query(User).filter_by(email=email, status="active").first()
                )
                if not user:
                    logging.warning(
                        f"Password reset update failed: No user found with email {self.anonymize_email(email)}."
                    )
                    return {"error": "User not found."}, 404

                # Verify OTP code
                if str(user.reset_code) != otp:
                    user.reset_try += 1
                    if user.reset_try > 5:
                        user.status = "inactive"
                        user.reset_try = 0
                        user.reset_code = None
                        logging.warning(
                            f"User {self.anonymize_email(email)} disabled after 5 failed OTP attempts."
                        )
                        return {
                            "error": "Too many incorrect attempts. User has been disabled."
                        }, 403
                    logging.warning(
                        f"Incorrect OTP for email {self.anonymize_email(email)}. Attempt {user.reset_try}/5."
                    )
                    return {"error": "Invalid OTP. Please try again."}, 401

                # Validate new password
                password_errors = self.password_policy.test(new_password)
                if password_errors:
                    logging.warning(
                        "Password reset update failed: New password does not meet policy requirements."
                    )
                    return {
                        "error": "New password must be at least 8 characters long and include uppercase letters, numbers, and special characters."
                    }, 400

                # Update password
                user.password = generate_password_hash(new_password)
                user.reset_try = 0
                user.reset_code = None
                logging.info(
                    f"Password changed successfully for email {self.anonymize_email(email)}."
                )
        except SQLAlchemyError as e:
            logging.error(
                f"Failed to change password for email {self.anonymize_email(email)}: {e}"
            )
            return {"error": "An error occurred while updating the password"}, 500

        return {"message": "Password updated successfully"}, 200

    def anonymize_email(self, email):
        """
        Anonymize email for logging purposes.
        """
        parts = email.split("@")
        if len(parts) == 2:
            return parts[0][:2] + "***@" + parts[1]
        return "***"

    def anonymize_mobile(self, mobile):
        """
        Anonymize mobile number for logging purposes.
        """
        return mobile[:3] + "****" + mobile[-4:]
