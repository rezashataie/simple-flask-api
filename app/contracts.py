import json
import os


class ContractInfo:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    ABIS_DIR = os.path.join(BASE_DIR, "../abi")

    CREATE_WALLET = {
        "address": "0x5da97814449Ee64164791834E04d7a821B43237e",
        "abi": "create_wallet_abi.json",
        "network": "Polygon",
    }

    USDT_POLYGON = {
        "address": "0xc2132D05D31c914a87C6611C10748AEb04B58e8F",
        "abi": "usdt_polygon_abi.json",
        "network": "Polygon",
    }

    REPOINT = {
        "address": "0x3EE1BBD5C99177f407200fAF8413285F7fc60EDD",
        "abi": "repoint_abi.json",
        "network": "Polygon",
    }

    REPOINT_PLUS = {
        "address": "0xFb00e3865b3431823ded138280A82C8741CCCEDD",
        "abi": "repoint_plus_abi.json",
        "network": "Polygon",
    }

    @classmethod
    def get_abi(cls, abi):
        abi_path = os.path.join(cls.ABIS_DIR, abi)
        try:
            with open(abi_path, "r") as file:
                abi_data = json.load(file)

                if isinstance(abi_data, list):
                    return abi_data

                if isinstance(abi_data, dict) and "abi" in abi_data:
                    return abi_data["abi"]

                raise ValueError(f"Invalid ABI format in file '{abi}'.")
        except FileNotFoundError:
            raise FileNotFoundError(f"ABI file '{abi}' not found in '{cls.ABIS_DIR}'.")
        except json.JSONDecodeError:
            raise ValueError(f"Error decoding JSON in ABI file '{abi}'.")
