import json
import os


class ContractInfo:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    ABIS_DIR = os.path.join(BASE_DIR, "../abi")

    CREATE_WALLET = {
        "address": "0x34170e3197ad3511f476E8Fc6F9ddCE578758974",
        "abi_file": "create_wallet_abi.json",
        "network": "Polygon",
    }

    USDT_POLYGON = {
        "address": "0xc2132D05D31c914a87C6611C10748AEb04B58e8F",
        "abi_file": "usdt_polygon_abi.json",
        "network": "Polygon",
    }

    REPOINT = {
        "address": "0x3EE1BBD5C99177f407200fAF8413285F7fc60EDD",
        "abi_file": "repoint_abi.json",
        "network": "Polygon",
    }

    @classmethod
    def get_abi(cls, abi_file):
        abi_path = os.path.join(cls.ABIS_DIR, abi_file)
        try:
            with open(abi_path, "r") as file:
                abi_data = json.load(file)
                return abi_data.get("abi", [])
        except FileNotFoundError:
            raise FileNotFoundError(
                f"ABI file '{abi_file}' not found in '{cls.ABIS_DIR}'."
            )
        except json.JSONDecodeError:
            raise ValueError(f"Error decoding JSON in ABI file '{abi_file}'.")
