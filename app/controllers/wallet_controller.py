import json
import logging
import bleach
from app.models.wallet_model import Wallet
from app.helpers.db_helpers import session_scope
from app.helpers.response_helpers import api_response
from sqlalchemy.exc import SQLAlchemyError
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware
from eth_account import Account
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

    def transfer_usdt(self, data, user_id=None):
        """
        Transfer USDT from a wallet to another address.
        :param data: Dictionary containing 'wallet_id', 'to_address', and 'amount'.
        :param user_id: ID of the logged-in user (if applicable).
        """
        wallet_id = data.get("wallet_id")
        to_address = data.get("to_address")
        amount = data.get("amount")

        # Validate inputs
        if not wallet_id or not to_address or not amount:
            return api_response(
                success=False,
                message="Missing required fields: 'wallet_id', 'to_address', 'amount'.",
                errors={"missing_fields": "wallet_id, to_address, amount"},
                status_code=400,
            )

        # Ensure amount is a positive number
        try:
            amount = float(amount)
            if amount <= 0:
                raise ValueError("Amount must be greater than zero.")
        except ValueError as e:
            return api_response(
                success=False,
                message="Invalid amount.",
                errors={"amount": str(e)},
                status_code=400,
            )

        # Validate and convert to_address to checksum format
        try:
            to_address = Web3.to_checksum_address(to_address)
        except ValueError as e:
            return api_response(
                success=False,
                message="Invalid 'to_address' format.",
                errors={"to_address": str(e)},
                status_code=400,
            )

        # Retrieve wallet from database
        try:
            with session_scope() as session:
                wallet = session.query(Wallet).get(wallet_id)
                if not wallet:
                    return api_response(
                        success=False,
                        message="Wallet not found.",
                        errors={"wallet_id": "No wallet found with the given ID."},
                        status_code=404,
                    )

                # Ensure the wallet is on the Polygon network
                if wallet.network != "Polygon":
                    return api_response(
                        success=False,
                        message="Wallet is not on the Polygon network.",
                        errors={"network": "Wallet network must be 'Polygon'."},
                        status_code=400,
                    )

                # Decrypt the private key
                try:
                    private_key = wallet.get_private_key()
                    wallet_address = wallet.address
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

        except SQLAlchemyError as e:
            logging.error(f"Database error: {e}")
            return api_response(
                success=False,
                message="Database error.",
                errors={"database": str(e)},
                status_code=500,
            )

        try:
            POLYGON_RPC_URL = "https://polygon-rpc.com"
            w3 = Web3(Web3.HTTPProvider(POLYGON_RPC_URL))
            w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

            USDT_CONTRACT_ADDRESS = Web3.to_checksum_address(
                "0xc2132d05d31c914a87c6611c10748aeb04b58e8f"
            )

            with open("abi/usdt_polygon_abi.json", "r") as abi_file:
                USDT_ABI = json.load(abi_file)

            usdt_contract = w3.eth.contract(address=USDT_CONTRACT_ADDRESS, abi=USDT_ABI)

            amount_in_smallest_unit = int(amount * 10**6)

            nonce = w3.eth.get_transaction_count(wallet_address)

            tx = usdt_contract.functions.transfer(
                to_address, amount_in_smallest_unit
            ).build_transaction(
                {
                    "chainId": 137,  # Polygon chain ID
                    "gas": 100000,  # Estimate gas; adjust as needed
                    "gasPrice": w3.to_wei("50", "gwei"),
                    "nonce": nonce,
                }
            )

            signed_tx = w3.eth.account.sign_transaction(tx, private_key=private_key)

            tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)

            logging.info(f"USDT transfer initiated: tx_hash={tx_hash.hex()}")

            return api_response(
                success=True,
                message="USDT transfer initiated.",
                data={"tx_hash": tx_hash.hex()},
                status_code=200,
            )

        except Exception as e:
            logging.error(f"Failed to transfer USDT: {e}")
            return api_response(
                success=False,
                message="Failed to transfer USDT.",
                errors={"exception": str(e)},
                status_code=500,
            )
