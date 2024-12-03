from flask import Blueprint, request
from app.controllers.wallet_controller import WalletController
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import limiter

wallet_bp = Blueprint("wallet", __name__, url_prefix="/wallet")

wallet_controller = WalletController()


@wallet_bp.route("/create", methods=["POST"])
@jwt_required()
@limiter.limit("5 per minute")
def create_wallet_route():
    """
    Route for creating a new wallet.
    """
    user_id = get_jwt_identity()
    data = request.get_json()
    response, status_code = wallet_controller.create_wallet(data, user_id)
    return response, status_code


@wallet_bp.route("/list", methods=["GET"])
@jwt_required()
def get_wallets_route():
    """
    Route for retrieving all wallets.
    """
    user_id = get_jwt_identity()
    response, status_code = wallet_controller.get_wallets(user_id)
    return response, status_code


@wallet_bp.route("/<int:wallet_id>", methods=["GET"])
@jwt_required()
def get_wallet_by_id_route(wallet_id):
    """
    Route for retrieving wallet details by ID.
    """
    user_id = get_jwt_identity()
    response, status_code = wallet_controller.get_wallet_by_id(wallet_id, user_id)
    return response, status_code


# دسترسی به کلید خصوصی باید محدود شود
# @wallet_bp.route("/<int:wallet_id>/private-key", methods=["GET"])
# @jwt_required()
# def get_private_key_route(wallet_id):
#     """
#     Route for retrieving the private key of a wallet.
#     """
#     user_id = get_jwt_identity()
#     response, status_code = wallet_controller.get_private_key(wallet_id, user_id)
#     return response, status_code
