import json
import logging
from app.models.wallet_model import Wallet
from app.helpers.db_helpers import session_scope
from app.helpers.response_helpers import api_response
from sqlalchemy.exc import SQLAlchemyError
from web3 import Web3
from web3.types import HexBytes
from web3.datastructures import AttributeDict
from web3.middleware import ExtraDataToPOAMiddleware
from cryptography.fernet import InvalidToken


class ContractController:
    """
    A controller for interacting with a smart contract on the Polygon network.
    """

    def __init__(self):
        self.rpc_url = "https://polygon-rpc.com"
        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        self.w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

        with open("abi/create_wallet_abi.json", "r") as abi_file:
            self.contract_abi = json.load(abi_file)

        self.contract_address = self.w3.to_checksum_address(
            "0x34170e3197ad3511f476E8Fc6F9ddCE578758974"
        )

        self.contract = self.w3.eth.contract(
            address=self.contract_address, abi=self.contract_abi
        )

    def call_function(self, data):
        """
        Call a read-only function from the contract.
        :param data: Dictionary containing 'function_name' and optional 'args'.
        """
        function_name = data.get("function_name")
        args = data.get("args", [])

        if not function_name:
            return api_response(
                success=False,
                message="Function name is required.",
                errors={"missing_fields": "function_name"},
                status_code=400,
            )

        try:
            contract_function = getattr(self.contract.functions, function_name)

            result = contract_function(*args).call()

            return api_response(
                success=True,
                message="Function executed successfully.",
                data={"result": result},
            )
        except Exception as e:
            logging.error(f"Error calling function {function_name}: {e}")
            return api_response(
                success=False,
                message="Error calling contract function.",
                errors={"exception": str(e)},
                status_code=500,
            )

    def send_transaction(self, data):
        """
        Send a write transaction to the contract.
        :param data: Dictionary containing 'function_name', 'args', and 'wallet_id'.
        """
        function_name = data.get("function_name")
        args = data.get("args", [])
        wallet_id = data.get("wallet_id")

        if not function_name or not wallet_id:
            return api_response(
                success=False,
                message="Function name and wallet ID are required.",
                errors={"missing_fields": "function_name, wallet_id"},
                status_code=400,
            )

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

                if wallet.network != "Polygon":
                    return api_response(
                        success=False,
                        message="Wallet is not on the Polygon network.",
                        errors={"network": "Wallet network must be 'Polygon'."},
                        status_code=400,
                    )

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

            contract_function = getattr(self.contract.functions, function_name)

            nonce = self.w3.eth.get_transaction_count(wallet_address)
            transaction = contract_function(*args).build_transaction(
                {
                    "chainId": 137,
                    "gas": 200000,
                    "gasPrice": self.w3.eth.gas_price,
                    "nonce": nonce,
                }
            )

            signed_tx = self.w3.eth.account.sign_transaction(
                transaction, private_key=private_key
            )

            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)

            logging.info(f"Transaction sent: tx_hash={tx_hash.hex()}")

            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            logging.info(f"receipt: {receipt}")
            receipt_converted = self.convert_hexbytes(receipt)
            logging.info(f"receipt_converted: {receipt_converted}")

            if receipt["status"] == 1:
                return api_response(
                    success=True,
                    message="Transaction completed successfully.",
                    data={"tx_hash": tx_hash.hex(), "receipt": receipt},
                    status_code=200,
                )
            else:
                return api_response(
                    success=False,
                    message="Transaction failed.",
                    data={"tx_hash": tx_hash.hex(), "receipt": receipt},
                    status_code=400,
                )

        except SQLAlchemyError as e:
            logging.error(f"Database error while fetching wallet {wallet_id}: {e}")
            return api_response(
                success=False,
                message="Database error.",
                errors={"database": str(e)},
                status_code=500,
            )
        except Exception as e:
            logging.error(f"Error sending transaction for {function_name}: {e}")
            return api_response(
                success=False,
                message="Error sending contract transaction.",
                errors={"exception": str(e)},
                status_code=500,
            )

    def convert_hexbytes(self, obj):
        if isinstance(obj, HexBytes):
            return obj.hex()
        if isinstance(obj, AttributeDict):
            return {k: self.convert_hexbytes(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.convert_hexbytes(item) for item in obj]
        return obj
