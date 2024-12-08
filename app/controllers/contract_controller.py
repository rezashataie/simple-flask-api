import json
import logging
import bleach
from hexbytes import HexBytes
from app.models.wallet_model import Wallet
from app.helpers.db_helpers import session_scope
from app.helpers.response_helpers import api_response
from sqlalchemy.exc import SQLAlchemyError
from web3 import Web3
from web3.datastructures import AttributeDict
from web3.middleware import ExtraDataToPOAMiddleware
from cryptography.fernet import InvalidToken
from app.errors import ErrorCodes, ERROR_MESSAGES


class ContractController:
    """
    A controller for interacting with a smart contract on the Polygon network.
    """

    def __init__(self):
        # Polygon RPC URL
        self.rpc_url = "https://polygon-rpc.com"
        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        self.w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

        # Load contract ABI
        with open("abi/create_wallet_abi.json", "r") as abi_file:
            self.contract_abi = json.load(abi_file)

        # Contract address
        self.contract_address = self.w3.to_checksum_address(
            "0xAF356498B019199C1481443892cCEd360E0F36CA"
        )

        # Contract instance
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
            # Get the function from the contract
            contract_function = getattr(self.contract.functions, function_name)

            # Call the function
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
        wallet_id = data.get("wallet_id")  # Use wallet ID instead of private key

        if not function_name or not wallet_id:
            return api_response(
                success=False,
                message="Function name and wallet ID are required.",
                errors={"missing_fields": "function_name, wallet_id"},
                status_code=400,
            )

        try:
            # Fetch wallet details from the database
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

            # Get the function from the contract
            contract_function = getattr(self.contract.functions, function_name)

            # Build the transaction
            nonce = self.w3.eth.get_transaction_count(wallet_address)
            transaction = contract_function(*args).build_transaction(
                {
                    "chainId": 137,  # Polygon chain ID
                    "gas": 200000,  # Adjust gas limit as needed
                    "gasPrice": self.w3.eth.gas_price,
                    "nonce": nonce,
                }
            )

            # Sign the transaction
            signed_tx = self.w3.eth.account.sign_transaction(
                transaction, private_key=private_key
            )

            # Send the transaction
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)

            logging.info(f"Transaction sent: tx_hash={tx_hash.hex()}")

            # Wait for the transaction receipt
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            # Convert receipt to a serializable format
            receipt_dict = self._convert_receipt_to_serializable(receipt)

            # Check the status of the transaction
            if receipt["status"] == 1:
                return api_response(
                    success=True,
                    message="Transaction completed successfully.",
                    data={"tx_hash": tx_hash.hex(), "receipt": receipt_dict},
                    status_code=200,
                )
            else:
                return api_response(
                    success=False,
                    message="Transaction failed.",
                    data={"tx_hash": tx_hash.hex(), "receipt": receipt_dict},
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

    def _convert_receipt_to_serializable(self, receipt):
        """
        Convert a transaction receipt to a JSON-serializable format.
        :param receipt: Transaction receipt object.
        :return: JSON-serializable dictionary.
        """
        serializable_receipt = {}
        for key, value in receipt.items():
            if isinstance(value, HexBytes):
                serializable_receipt[key] = value.hex()
            elif isinstance(value, list):
                serializable_receipt[key] = [
                    (
                        self._convert_receipt_to_serializable(item)
                        if isinstance(item, AttributeDict)
                        else item
                    )
                    for item in value
                ]
            elif isinstance(value, AttributeDict):
                serializable_receipt[key] = self._convert_receipt_to_serializable(value)
            else:
                serializable_receipt[key] = value
        return serializable_receipt
