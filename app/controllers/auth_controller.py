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
from app.helpers.response_helpers import api_response
from app.errors import ErrorCodes, ERROR_MESSAGES


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
            return api_response(
                success=False,
                message=ERROR_MESSAGES[ErrorCodes.MISSING_FIELDS],
                errors={"missing_fields": "mobile, email, password, name"},
                status_code=400,
            )

        # Validate email
        try:
            valid_email = validate_email(email)
            email = valid_email.email  # Normalized email
        except EmailNotValidError:
            logging.warning(
                f"Registration failed: Invalid email format for {self.anonymize_email(email)}."
            )
            return api_response(
                success=False,
                message=ERROR_MESSAGES[ErrorCodes.INVALID_EMAIL],
                errors={"email": ERROR_MESSAGES[ErrorCodes.INVALID_EMAIL]},
                status_code=400,
            )

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
            return api_response(
                success=False,
                message=ERROR_MESSAGES[ErrorCodes.INVALID_MOBILE],
                errors={"mobile": ERROR_MESSAGES[ErrorCodes.INVALID_MOBILE]},
                status_code=400,
            )

        # Validate password according to policy
        password_errors = self.password_policy.test(password)
        if password_errors:
            logging.warning(
                "Registration failed: Password does not meet policy requirements."
            )
            return api_response(
                success=False,
                message=ERROR_MESSAGES[ErrorCodes.INVALID_PASSWORD],
                errors={"password": ERROR_MESSAGES[ErrorCodes.INVALID_PASSWORD]},
                status_code=400,
            )

        # Validate name (only Persian or English letters and spaces)
        if not re.match(r"^[a-zA-Z\u0600-\u06FF\s]+$", name):
            logging.warning(f"Registration failed: Invalid name format for {name}.")
            return api_response(
                success=False,
                message=ERROR_MESSAGES[ErrorCodes.INVALID_NAME],
                errors={"name": ERROR_MESSAGES[ErrorCodes.INVALID_NAME]},
                status_code=400,
            )

        # Check for existing user with the same email or mobile
        try:
            with session_scope() as session:
                if session.query(User).filter_by(mobile=mobile).first():
                    logging.warning(
                        f"Registration failed: Mobile number {self.anonymize_mobile(mobile)} already exists."
                    )
                    return api_response(
                        success=False,
                        message=ERROR_MESSAGES[ErrorCodes.MOBILE_ALREADY_EXISTS],
                        errors={
                            "mobile": ERROR_MESSAGES[ErrorCodes.MOBILE_ALREADY_EXISTS]
                        },
                        status_code=409,
                    )

                if session.query(User).filter_by(email=email).first():
                    logging.warning(
                        f"Registration failed: Email {self.anonymize_email(email)} already exists."
                    )
                    return api_response(
                        success=False,
                        message=ERROR_MESSAGES[ErrorCodes.EMAIL_ALREADY_EXISTS],
                        errors={
                            "email": ERROR_MESSAGES[ErrorCodes.EMAIL_ALREADY_EXISTS]
                        },
                        status_code=409,
                    )

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
                session.flush()  # Flush the session to get new_user.id
                user_id = new_user.id  # Get the user_id before the session is closed

        except SQLAlchemyError as e:
            logging.error(
                f"Failed to register user {self.anonymize_mobile(mobile)}: {e}"
            )
            return api_response(
                success=False,
                message=ERROR_MESSAGES[ErrorCodes.UNEXPECTED_ERROR],
                errors={"database": str(e)},
                status_code=500,
            )

        logging.info(f"User {self.anonymize_mobile(mobile)} registered successfully.")

        # Send verification email
        try:
            self.email_service.send(
                subject="Welcome to Pan2mim!",
                recipients=[email],
                template_name="register",
                template_data={"name": name, "code": verify_code},
            )
        except Exception as e:
            logging.error(
                f"Failed to send verification email to {self.anonymize_email(email)}: {e}"
            )
            return api_response(
                success=False,
                message="Failed to send verification email.",
                errors={"email_service": str(e)},
                status_code=500,
            )

        return api_response(
            success=True,
            message="User registered successfully. Please check your email for the verification code.",
            data={"user_id": user_id},
            status_code=201,
        )

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
            return api_response(
                success=False,
                message=ERROR_MESSAGES[ErrorCodes.MISSING_FIELDS],
                errors={"missing_fields": "email, otp"},
                status_code=400,
            )

        # Validate email
        try:
            valid_email = validate_email(email)
            email = valid_email.email  # Normalized email
        except EmailNotValidError:
            logging.warning(
                f"Activation failed: Invalid email format for {self.anonymize_email(email)}."
            )
            return api_response(
                success=False,
                message=ERROR_MESSAGES[ErrorCodes.INVALID_EMAIL],
                errors={"email": ERROR_MESSAGES[ErrorCodes.INVALID_EMAIL]},
                status_code=400,
            )

        # Validate OTP code
        if not re.match(r"^\d{6}$", otp):
            logging.warning("Activation failed: Invalid OTP format.")
            return api_response(
                success=False,
                message="Invalid OTP format. It should be a 6-digit number.",
                errors={"otp": "Invalid format"},
                status_code=400,
            )

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
                    return api_response(
                        success=False,
                        message=ERROR_MESSAGES[ErrorCodes.USER_NOT_FOUND],
                        errors={"email": ERROR_MESSAGES[ErrorCodes.USER_NOT_FOUND]},
                        status_code=404,
                    )

                # Verify OTP code
                if str(user.verify_code) != otp:
                    user.verify_try += 1
                    if user.verify_try > 5:
                        session.delete(user)
                        logging.warning(
                            f"User {self.anonymize_email(email)} deleted after 5 failed OTP attempts."
                        )
                        return api_response(
                            success=False,
                            message=ERROR_MESSAGES[ErrorCodes.OTP_ATTEMPTS_EXCEEDED],
                            errors={
                                "otp": ERROR_MESSAGES[ErrorCodes.OTP_ATTEMPTS_EXCEEDED]
                            },
                            status_code=403,
                        )
                    logging.warning(
                        f"Incorrect OTP for email {self.anonymize_email(email)}. Attempt {user.verify_try}/5."
                    )
                    return api_response(
                        success=False,
                        message=ERROR_MESSAGES[ErrorCodes.INVALID_OTP],
                        errors={"otp": ERROR_MESSAGES[ErrorCodes.INVALID_OTP]},
                        status_code=401,
                    )

                # Activate user
                user.status = "active"
                user.verify_try = 0
                user.verify_code = None
                logging.info(
                    f"User {self.anonymize_email(email)} activated successfully."
                )
        except SQLAlchemyError as e:
            logging.error(f"Failed to activate user {self.anonymize_email(email)}: {e}")
            return api_response(
                success=False,
                message=ERROR_MESSAGES[ErrorCodes.UNEXPECTED_ERROR],
                errors={"database": str(e)},
                status_code=500,
            )

        return api_response(
            success=True, message="User activated successfully.", status_code=200
        )

    def login(self, data):
        """
        Log in a user using email and password.
        :param data: Dictionary containing email and password.
        """
        email = bleach.clean(data.get("email", "").strip().lower())
        password = bleach.clean(data.get("password", "").strip())

        if not email or not password:
            logging.warning("Login attempt with missing email or password.")
            return api_response(
                success=False,
                message=ERROR_MESSAGES[ErrorCodes.MISSING_FIELDS],
                errors={"missing_fields": "email, password"},
                status_code=400,
            )

        # Validate email
        try:
            valid_email = validate_email(email)
            email = valid_email.email  # Normalized email
        except EmailNotValidError:
            logging.warning(
                f"Login failed: Invalid email format for {self.anonymize_email(email)}."
            )
            return api_response(
                success=False,
                message=ERROR_MESSAGES[ErrorCodes.INVALID_CREDENTIALS],
                errors={"email": ERROR_MESSAGES[ErrorCodes.INVALID_EMAIL]},
                status_code=401,
            )

        try:
            with session_scope() as session:
                user = session.query(User).filter_by(email=email).first()
                if not user or not check_password_hash(user.password, password):
                    logging.warning(
                        f"Failed login attempt for email: {self.anonymize_email(email)}"
                    )
                    return api_response(
                        success=False,
                        message=ERROR_MESSAGES[ErrorCodes.INVALID_CREDENTIALS],
                        errors={
                            "credentials": ERROR_MESSAGES[
                                ErrorCodes.INVALID_CREDENTIALS
                            ]
                        },
                        status_code=401,
                    )

                if user.status != "active":
                    logging.warning(
                        f"Login failed: Account inactive for email {self.anonymize_email(email)}."
                    )
                    return api_response(
                        success=False,
                        message=ERROR_MESSAGES[ErrorCodes.ACCOUNT_INACTIVE],
                        errors={"status": ERROR_MESSAGES[ErrorCodes.ACCOUNT_INACTIVE]},
                        status_code=403,
                    )

                # Generate JWT token
                additional_claims = {"name": user.name}
                access_token = create_access_token(
                    identity=user.id, additional_claims=additional_claims
                )
                logging.info(
                    f"User {self.anonymize_email(email)} logged in successfully."
                )
                return api_response(
                    success=True,
                    message="Login successful.",
                    data={"token": access_token},
                    status_code=200,
                )
        except SQLAlchemyError as e:
            logging.error(f"Failed to log in user {self.anonymize_email(email)}: {e}")
            return api_response(
                success=False,
                message=ERROR_MESSAGES[ErrorCodes.UNEXPECTED_ERROR],
                errors={"database": str(e)},
                status_code=500,
            )

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
            return api_response(
                success=False,
                message=ERROR_MESSAGES[ErrorCodes.MISSING_FIELDS],
                errors={"missing_fields": "current_password, new_password"},
                status_code=400,
            )

        try:
            with session_scope() as session:
                user = session.query(User).get(user_id)
                if not user:
                    logging.warning(
                        f"Password change failed: User ID {user_id} not found."
                    )
                    return api_response(
                        success=False,
                        message=ERROR_MESSAGES[ErrorCodes.USER_NOT_FOUND],
                        errors={"user_id": ERROR_MESSAGES[ErrorCodes.USER_NOT_FOUND]},
                        status_code=404,
                    )

                # Verify current password
                if not check_password_hash(user.password, current_password):
                    logging.warning(
                        f"Password change failed: Incorrect current password for user ID {user_id}."
                    )
                    return api_response(
                        success=False,
                        message="Current password is incorrect.",
                        errors={"current_password": "Incorrect password."},
                        status_code=401,
                    )

                # Validate new password
                password_errors = self.password_policy.test(new_password)
                if password_errors:
                    logging.warning(
                        "Password change failed: New password does not meet policy requirements."
                    )
                    return api_response(
                        success=False,
                        message=ERROR_MESSAGES[ErrorCodes.INVALID_PASSWORD],
                        errors={
                            "new_password": ERROR_MESSAGES[ErrorCodes.INVALID_PASSWORD]
                        },
                        status_code=400,
                    )

                # Update password
                user.password = generate_password_hash(new_password)
                logging.info(f"Password changed successfully for user ID {user_id}.")
        except SQLAlchemyError as e:
            logging.error(f"Failed to change password for user ID {user_id}: {e}")
            return api_response(
                success=False,
                message=ERROR_MESSAGES[ErrorCodes.UNEXPECTED_ERROR],
                errors={"database": str(e)},
                status_code=500,
            )

        return api_response(
            success=True, message="Password updated successfully.", status_code=200
        )

    def reset_password_request(self, data):
        """
        Request a password reset by sending a reset code to the user's email.
        :param data: Dictionary containing email.
        """
        email = bleach.clean(data.get("email", "").strip().lower())

        if not email:
            logging.warning("Password reset failed: Missing email.")
            return api_response(
                success=False,
                message=ERROR_MESSAGES[ErrorCodes.MISSING_FIELDS],
                errors={"missing_fields": "email"},
                status_code=400,
            )

        # Validate email
        try:
            valid_email = validate_email(email)
            email = valid_email.email  # Normalized email
        except EmailNotValidError:
            logging.warning(
                f"Password reset failed: Invalid email format for {self.anonymize_email(email)}."
            )
            return api_response(
                success=False,
                message=ERROR_MESSAGES[ErrorCodes.INVALID_EMAIL],
                errors={"email": ERROR_MESSAGES[ErrorCodes.INVALID_EMAIL]},
                status_code=400,
            )

        try:
            with session_scope() as session:
                user = session.query(User).filter_by(email=email).first()
                if not user:
                    logging.warning(
                        f"Password reset: User not found for {self.anonymize_email(email)}"
                    )
                    return api_response(
                        success=False,
                        message=ERROR_MESSAGES[ErrorCodes.USER_NOT_FOUND],
                        errors={"email": ERROR_MESSAGES[ErrorCodes.USER_NOT_FOUND]},
                        status_code=404,
                    )

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
            return api_response(
                success=False,
                message=ERROR_MESSAGES[ErrorCodes.UNEXPECTED_ERROR],
                errors={"database": str(e)},
                status_code=500,
            )

        # Send reset code via email
        try:
            self.email_service.send(
                subject="Reset your password!",
                recipients=[email],
                template_name="reset-password",
                template_data={"name": user.name, "code": reset_code},
            )
        except Exception as e:
            logging.error(
                f"Failed to send reset email to {self.anonymize_email(email)}: {e}"
            )
            return api_response(
                success=False,
                message="Failed to send reset email.",
                errors={"email_service": str(e)},
                status_code=500,
            )

        return api_response(
            success=True, message="Reset code sent successfully.", status_code=201
        )

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
            return api_response(
                success=False,
                message=ERROR_MESSAGES[ErrorCodes.MISSING_FIELDS],
                errors={"missing_fields": "email, otp, new_password"},
                status_code=400,
            )

        # Validate email
        try:
            valid_email = validate_email(email)
            email = valid_email.email  # Normalized email
        except EmailNotValidError:
            logging.warning(
                f"Password reset update failed: Invalid email format for {self.anonymize_email(email)}."
            )
            return api_response(
                success=False,
                message=ERROR_MESSAGES[ErrorCodes.INVALID_EMAIL],
                errors={"email": ERROR_MESSAGES[ErrorCodes.INVALID_EMAIL]},
                status_code=400,
            )

        # Validate OTP code
        if not re.match(r"^\d{6}$", otp):
            logging.warning("Password reset update failed: Invalid OTP format.")
            return api_response(
                success=False,
                message="Invalid OTP format. It should be a 6-digit number.",
                errors={"otp": "Invalid format"},
                status_code=400,
            )

        try:
            with session_scope() as session:
                user = (
                    session.query(User).filter_by(email=email, status="active").first()
                )
                if not user:
                    logging.warning(
                        f"Password reset update failed: No user found with email {self.anonymize_email(email)}."
                    )
                    return api_response(
                        success=False,
                        message=ERROR_MESSAGES[ErrorCodes.USER_NOT_FOUND],
                        errors={"email": ERROR_MESSAGES[ErrorCodes.USER_NOT_FOUND]},
                        status_code=404,
                    )

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
                        return api_response(
                            success=False,
                            message=ERROR_MESSAGES[ErrorCodes.OTP_ATTEMPTS_EXCEEDED],
                            errors={
                                "otp": ERROR_MESSAGES[ErrorCodes.OTP_ATTEMPTS_EXCEEDED]
                            },
                            status_code=403,
                        )
                    logging.warning(
                        f"Incorrect OTP for email {self.anonymize_email(email)}. Attempt {user.reset_try}/5."
                    )
                    return api_response(
                        success=False,
                        message=ERROR_MESSAGES[ErrorCodes.INVALID_OTP],
                        errors={"otp": ERROR_MESSAGES[ErrorCodes.INVALID_OTP]},
                        status_code=401,
                    )

                # Validate new password
                password_errors = self.password_policy.test(new_password)
                if password_errors:
                    logging.warning(
                        "Password reset update failed: New password does not meet policy requirements."
                    )
                    return api_response(
                        success=False,
                        message=ERROR_MESSAGES[ErrorCodes.INVALID_PASSWORD],
                        errors={
                            "new_password": ERROR_MESSAGES[ErrorCodes.INVALID_PASSWORD]
                        },
                        status_code=400,
                    )

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
            return api_response(
                success=False,
                message=ERROR_MESSAGES[ErrorCodes.UNEXPECTED_ERROR],
                errors={"database": str(e)},
                status_code=500,
            )

        return api_response(
            success=True, message="Password updated successfully.", status_code=200
        )

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
