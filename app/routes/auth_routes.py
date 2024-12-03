from flask import Blueprint, request, jsonify
from app.controllers.auth_controller import AuthController
from flask_jwt_extended import jwt_required, get_jwt_identity


auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@auth_bp.route("/register", methods=["POST"])
def register_route():
    """
    Route for user registration.
    """
    data = request.get_json()
    response = AuthController.register(data)
    return jsonify(response)


@auth_bp.route("/register/activate", methods=["POST"])
def activate_user_route():
    """
    Route for user activation via verification code.
    """
    data = request.get_json()
    response = AuthController.activate_user(data)
    return jsonify(response)


@auth_bp.route("/login", methods=["POST"])
def login_route():
    """
    Route for user login.
    """
    data = request.get_json()
    response = AuthController.login(data)
    return jsonify(response)


@auth_bp.route("/change-password", methods=["POST"])
@jwt_required()
def change_password_route():
    """
    Route for changing the user's password.
    """
    user_id = get_jwt_identity()
    data = request.get_json()
    response = AuthController.change_password(data, user_id)
    return jsonify(response)


@auth_bp.route("/reset-password", methods=["POST"])
def reset_password_route():
    """
    Route for requesting a password reset code.
    """
    data = request.get_json()
    response = AuthController.reset_password_request(data)
    return jsonify(response)


@auth_bp.route("/reset-password/confirm", methods=["POST"])
def reset_password_confirm_route():
    """
    Route for confirming the password reset using the code.
    """
    data = request.get_json()
    response = AuthController.reset_password_confirm(data)
    return jsonify(response)
