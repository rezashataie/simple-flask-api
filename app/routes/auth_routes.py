from flask import Blueprint, request, jsonify
from app.controllers.auth_controller import register_controller, login_controller, change_password_controller
from app.helpers.auth_helpers import token_required

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/auth/register', methods=['POST'])
def register_route():
    data = request.get_json()
    response = register_controller(data)
    return jsonify(response)


@auth_bp.route('/auth/login', methods=['POST'])
def login_route():
    data = request.get_json()
    response = login_controller(data)
    return jsonify(response)


@auth_bp.route('/auth/change-password', methods=['POST'])
@token_required
def change_password_route(user_id):
    data = request.get_json()
    response = change_password_controller(data, user_id)
    return jsonify(response)