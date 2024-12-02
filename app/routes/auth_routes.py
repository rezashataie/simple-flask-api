from flask import Blueprint, request, jsonify
from app.controllers.auth_controller import AuthController
from app.helpers.auth_helpers import token_required

# Create Blueprint
auth_bp = Blueprint("auth", __name__)

# Instantiate the AuthController
auth_controller = AuthController()


@auth_bp.route("/auth/register", methods=["POST"])
def register_route():
    """
    Handle user registration.
    """
    data = request.get_json()
    response = auth_controller.register(data)
    return jsonify(response[0]), response[1]


@auth_bp.route("/auth/register/active-user", methods=["POST"])
def active_user_route():
    """
    Handle user activation.
    """
    data = request.get_json()
    response = auth_controller.activate_user(data)
    return jsonify(response[0]), response[1]


@auth_bp.route("/auth/login", methods=["POST"])
def login_route():
    """
    Handle user login.
    """
    data = request.get_json()
    response = auth_controller.login(data)
    return jsonify(response[0]), response[1]


@auth_bp.route("/auth/change-password", methods=["POST"])
@token_required
def change_password_route(user_id):
    """
    Handle password change for logged-in users.
    """
    data = request.get_json()
    response = auth_controller.change_password(data, user_id)
    return jsonify(response[0]), response[1]


@auth_bp.route("/auth/reset-password", methods=["POST"])
def reset_password_route():
    """
    Request a password reset.
    """
    data = request.get_json()
    response = auth_controller.reset_password_request(data)
    return jsonify(response[0]), response[1]


@auth_bp.route("/auth/reset-password/update", methods=["POST"])
def reset_password_update_route():
    """
    Handle password reset update.
    """
    data = request.get_json()
    response = auth_controller.reset_password_update(data)
    return jsonify(response[0]), response[1]
