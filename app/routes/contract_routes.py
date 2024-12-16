from flask import Blueprint, request
from app.controllers.contract_controller import ContractController
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.helpers.decorators import admin_required
from app import limiter

contract_bp = Blueprint("contract", __name__, url_prefix="/contract")

# Instantiate the controller
contract_controller = ContractController()


@contract_bp.route("/call", methods=["POST"])
@jwt_required()
@admin_required
@limiter.limit("50 per minute")
def call_function_route():
    """
    Route to call a read-only function from the smart contract.
    """
    data = request.get_json()
    user_id = get_jwt_identity()
    response, status_code = contract_controller.call_function(data)
    return response, status_code


@contract_bp.route("/send", methods=["POST"])
@jwt_required()
@admin_required
@limiter.limit("20 per minute")
def send_transaction_route():
    """
    Route to send a transaction to the smart contract.
    """
    data = request.get_json()
    user_id = get_jwt_identity()
    response, status_code = contract_controller.send_transaction(data)
    return response, status_code


@contract_bp.route("/get-contract-wallet", methods=["POST"])
@jwt_required()
@admin_required
@limiter.limit("20 per minute")
def get_contract_wallet_route():
    """
    Route to send a transaction to the smart contract.
    """
    response, status_code = contract_controller.get_contract_wallet()
    return response, status_code
