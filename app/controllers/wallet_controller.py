import logging
import bleach
from app.models.wallet_model import Wallet
from app.helpers.db_helpers import session_scope
from app.helpers.response_helpers import api_response
from sqlalchemy.exc import SQLAlchemyError
from eth_account import Account
from flask_jwt_extended import get_jwt_identity
from cryptography.fernet import InvalidToken
from app.errors import ErrorCodes, ERROR_MESSAGES


class WalletController:
    def create_wallet(self, data, user_id=None):
        network = bleach.clean(data.get("network", "").strip())
        count = bleach.clean(data.get("count", "").strip())

        if not network or not count:
            return api_response(
                success=False,
                message=ERROR_MESSAGES[ErrorCodes.MISSING_FIELDS],
                errors={"missing_fields": "nwtwork, count"},
                status_code=400,
            )

        if network not in ["Polygon", "Ethereum", "BEP20"]:
            logging.warning(f"Invalid network specified: {network}")
            return api_response(
                success=False,
                message="Invalid network specified.",
                errors={
                    "network": "Supported networks are 'Polygon', 'Ethereum' and 'BEP20'."
                },
                status_code=400,
            )

        if not count.isdigit():
            return api_response(
                success=False,
                message="Invalid count. It must be a number.",
                errors={"count": "count must contain only digits."},
                status_code=400,
            )

        try:
            count = int(count)
            if count <= 0:
                raise ValueError("Count must be a positive integer.")
        except ValueError as e:
            return api_response(
                success=False,
                message="Invalid count value.",
                errors={"count": str(e)},
                status_code=400,
            )

        wallets_data = []

        try:
            with session_scope() as session:
                for _ in range(count):
                    account = Account.create()
                    private_key = account.key.hex()
                    address = account.address

                    new_wallet = Wallet(address=address, network=network)
                    new_wallet.set_private_key(private_key)

                    session.add(new_wallet)
                    session.flush()
                    wallet_id = new_wallet.id

                    wallets_data.append(
                        {"wallet_id": wallet_id, "address": address, "network": network}
                    )
        except SQLAlchemyError as e:
            logging.error(f"Failed to create wallets: {e}")
            return api_response(
                success=False,
                message=ERROR_MESSAGES[ErrorCodes.UNEXPECTED_ERROR],
                errors={"database": str(e)},
                status_code=500,
            )

        logging.info(f"{count} wallet(s) created successfully.")

        return api_response(
            success=True,
            message=f"{count} wallet(s) created successfully.",
            data={"wallets": wallets_data},
            status_code=201,
        )

    def get_wallets(self, user_id=None):
        try:
            with session_scope() as session:
                wallets = session.query(Wallet).all()
                wallets_data = [
                    {
                        "wallet_id": wallet.id,
                        "address": wallet.address,
                        "network": wallet.network,
                        "created_at": wallet.created_at.isoformat(),
                    }
                    for wallet in wallets
                ]
        except SQLAlchemyError as e:
            logging.error(f"Failed to retrieve wallets: {e}")
            return api_response(
                success=False,
                message=ERROR_MESSAGES[ErrorCodes.UNEXPECTED_ERROR],
                errors={"database": str(e)},
                status_code=500,
            )

        return api_response(
            success=True,
            message="Wallets retrieved successfully.",
            data={"wallets": wallets_data},
            status_code=200,
        )

    def get_wallet_by_id(self, wallet_id, user_id=None):
        try:
            with session_scope() as session:
                wallet = session.query(Wallet).get(wallet_id)
                if not wallet:
                    logging.warning(f"Wallet not found with ID {wallet_id}.")
                    return api_response(
                        success=False,
                        message="Wallet not found.",
                        errors={"wallet_id": "No wallet found with the given ID."},
                        status_code=404,
                    )

                wallet_data = {
                    "wallet_id": wallet.id,
                    "address": wallet.address,
                    "network": wallet.network,
                    "created_at": wallet.created_at.isoformat(),
                }

        except SQLAlchemyError as e:
            logging.error(f"Failed to retrieve wallet with ID {wallet_id}: {e}")
            return api_response(
                success=False,
                message=ERROR_MESSAGES[ErrorCodes.UNEXPECTED_ERROR],
                errors={"database": str(e)},
                status_code=500,
            )

        return api_response(
            success=True,
            message="Wallet retrieved successfully.",
            data=wallet_data,
            status_code=200,
        )

    def get_private_key(self, data, user_id=None):
        wallet_id = bleach.clean(data.get("wallet_id", "").strip())

        if not wallet_id:
            return api_response(
                success=False,
                message=ERROR_MESSAGES[ErrorCodes.MISSING_FIELDS],
                errors={"missing_fields": "wallet_id"},
                status_code=400,
            )

        if not wallet_id.isdigit():
            return api_response(
                success=False,
                message="Invalid wallet_id. It must be a number.",
                errors={"wallet_id": "wallet_id must contain only digits."},
                status_code=400,
            )

        try:
            with session_scope() as session:
                wallet = session.query(Wallet).get(wallet_id)
                if not wallet:
                    logging.warning(f"Wallet not found with ID {wallet_id}.")
                    return api_response(
                        success=False,
                        message="Wallet not found.",
                        errors={"wallet_id": "No wallet found with the given ID."},
                        status_code=404,
                    )

                try:
                    private_key = wallet.get_private_key()
                except InvalidToken as e:
                    logging.error(
                        f"Failed to decrypt private key for wallet ID {wallet_id}: {e}"
                    )
                    return api_response(
                        success=False,
                        message="Failed to decrypt private key.",
                        errors={"decryption": str(e)},
                        status_code=500,
                    )

                wallet_data = {
                    "wallet_id": wallet.id,
                    "address": wallet.address,
                    "private_key": private_key,
                    "network": wallet.network,
                    "created_at": wallet.created_at.isoformat(),
                }

        except SQLAlchemyError as e:
            logging.error(f"Failed to retrieve wallet with ID {wallet_id}: {e}")
            return api_response(
                success=False,
                message=ERROR_MESSAGES[ErrorCodes.UNEXPECTED_ERROR],
                errors={"database": str(e)},
                status_code=500,
            )

        logging.warning(f"Private key retrieved for wallet ID {wallet_id}.")

        return api_response(
            success=True,
            message="Private key retrieved successfully.",
            data=wallet_data,
            status_code=200,
        )
