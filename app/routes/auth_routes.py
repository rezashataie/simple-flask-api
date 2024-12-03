from flask import Blueprint, request
from app.controllers.auth_controller import AuthController
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import limiter

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

auth_controller = AuthController()


@auth_bp.route("/register", methods=["POST"])
@limiter.limit("50 per minute")
def register_route():
    """
    Route for user registration.
    """
    data = request.get_json()
    response, status_code = auth_controller.register(data)
    return response, status_code


@auth_bp.route("/activate", methods=["POST"])
@limiter.limit("10 per hour")
def activate_user_route():
    """
    Route for user activation via verification code.
    """
    data = request.get_json()
    response, status_code = auth_controller.activate_user(data)
    return response, status_code


@auth_bp.route("/login", methods=["POST"])
@limiter.limit("10 per minute")
def login_route():
    """
    Route for user login.
    """
    data = request.get_json()
    response, status_code = auth_controller.login(data)
    return response, status_code


@auth_bp.route("/change-password", methods=["POST"])
@jwt_required()
@limiter.limit("5 per minute")
def change_password_route():
    """
    Route for changing the user's password.
    """
    user_id = get_jwt_identity()
    data = request.get_json()
    response, status_code = auth_controller.change_password(data, user_id)
    return response, status_code


@auth_bp.route("/reset-password-request", methods=["POST"])
@limiter.limit("5 per hour")
def reset_password_request_route():
    """
    Route for requesting a password reset code.
    """
    data = request.get_json()
    response, status_code = auth_controller.reset_password_request(data)
    return response, status_code


@auth_bp.route("/reset-password-update", methods=["POST"])
@limiter.limit("5 per hour")
def reset_password_update_route():
    """
    Route for updating the password after reset.
    """
    data = request.get_json()
    response, status_code = auth_controller.reset_password_update(data)
    return response, status_code
