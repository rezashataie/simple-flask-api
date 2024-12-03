import logging
from app.models.wallet_model import Wallet
from app.helpers.db_helpers import session_scope
from app.helpers.response_helpers import api_response
from sqlalchemy.exc import SQLAlchemyError
from eth_account import Account
from flask_jwt_extended import get_jwt_identity
from cryptography.fernet import InvalidToken
from app.errors import ErrorCodes, ERROR_MESSAGES


class WalletController:
    """
    This class handles all wallet-related actions including
    creating a wallet, retrieving wallets, and getting wallet details.
    """

    def create_wallet(self, data, user_id=None):
        """
        Create a new wallet.
        :param data: Dictionary containing network (optional).
        :param user_id: ID of the logged-in user (if applicable).
        """
        network = data.get("network", "Polygon").strip()

        # Validate network
        if network not in ["Polygon", "Ethereum"]:
            logging.warning(f"Invalid network specified: {network}")
            return api_response(
                success=False,
                message="Invalid network specified.",
                errors={"network": "Supported networks are 'Polygon' and 'Ethereum'."},
                status_code=400,
            )

        # Generate a new wallet
        account = Account.create()
        private_key = account.privateKey.hex()
        address = account.address

        # Create Wallet instance
        new_wallet = Wallet(address=address, network=network)
        new_wallet.set_private_key(private_key)

        # Save to database
        try:
            with session_scope() as session:
                session.add(new_wallet)
                session.flush()
                wallet_id = new_wallet.id
        except SQLAlchemyError as e:
            logging.error(f"Failed to create wallet: {e}")
            return api_response(
                success=False,
                message=ERROR_MESSAGES[ErrorCodes.UNEXPECTED_ERROR],
                errors={"database": str(e)},
                status_code=500,
            )

        logging.info(f"Wallet created successfully with ID {wallet_id}.")

        # Prepare response data
        response_data = {"wallet_id": wallet_id, "address": address, "network": network}

        return api_response(
            success=True,
            message="Wallet created successfully.",
            data=response_data,
            status_code=201,
        )

    def get_wallets(self, user_id=None):
        """
        Retrieve all wallets.
        :param user_id: ID of the logged-in user (if applicable).
        """
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
        """
        Retrieve wallet details by wallet ID.
        :param wallet_id: ID of the wallet.
        :param user_id: ID of the logged-in user (if applicable).
        """
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

    def get_private_key(self, wallet_id, user_id=None):
        """
        Retrieve the private key of a wallet (use with caution).
        :param wallet_id: ID of the wallet.
        :param user_id: ID of the logged-in user (if applicable).
        """
        # WARNING: Exposing private keys is a significant security risk.
        # This method should be secured and used only when absolutely necessary.

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

                # Decrypt private key
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

        # WARNING: Ensure that access to this method is strictly controlled.
        logging.warning(f"Private key retrieved for wallet ID {wallet_id}.")

        return api_response(
            success=True,
            message="Private key retrieved successfully.",
            data=wallet_data,
            status_code=200,
        )
