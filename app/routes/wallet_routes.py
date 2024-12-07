from flask import Blueprint, request
from app.controllers.wallet_controller import WalletController
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.helpers.decorators import admin_required
from app import limiter

wallet_bp = Blueprint("wallet", __name__, url_prefix="/wallet")

wallet_controller = WalletController()


@wallet_bp.route("/create", methods=["POST"])
@jwt_required()
@admin_required
@limiter.limit("50 per minute")
def create_wallet_route():
    user_id = get_jwt_identity()
    data = request.get_json()
    response, status_code = wallet_controller.create_wallet(data, user_id)
    return response, status_code


@wallet_bp.route("/get-private-key", methods=["POST"])
@jwt_required()
@admin_required
@limiter.limit("50 per minute")
def get_private_key_route():
    user_id = get_jwt_identity()
    data = request.get_json()
    response, status_code = wallet_controller.get_private_key(data, user_id)
    return response, status_code


@wallet_bp.route("/transfer-usdt", methods=["POST"])
@jwt_required()
@admin_required
@limiter.limit("50 per minute")
def transfer_usdt_route():
    user_id = get_jwt_identity()
    data = request.get_json()
    response, status_code = wallet_controller.transfer_usdt(data, user_id)
    return response, status_code


# @wallet_bp.route("/list", methods=["GET"])
# @jwt_required()
# @admin_required
# def get_wallets_route():
#     user_id = get_jwt_identity()
#     response, status_code = wallet_controller.get_wallets(user_id)
#     return response, status_code


# @wallet_bp.route("/<int:wallet_id>", methods=["GET"])
# @jwt_required()
# @admin_required
# def get_wallet_by_id_route(wallet_id):
#     user_id = get_jwt_identity()
#     response, status_code = wallet_controller.get_wallet_by_id(wallet_id, user_id)
#     return response, status_code
