from flask import Blueprint, request, jsonify
from app.controllers.auth_controller import register_user, login_user

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    response = register_user(data)
    return jsonify(response)


@auth_bp.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    response = login_user(data)
    return jsonify(response)
