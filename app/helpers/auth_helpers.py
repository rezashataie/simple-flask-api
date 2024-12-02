import jwt
import logging
from functools import wraps
from flask import request, jsonify, current_app as app


class TokenManager:
    """
    This class manages JWT tokens, including encoding and decoding.
    """

    @staticmethod
    def generate_token(payload, expiration_minutes):
        """
        Generate a JWT token.
        :param payload: Dictionary containing user data (e.g., user_id, name).
        :param expiration_minutes: Token expiration in minutes.
        :return: Encoded JWT token.
        """
        try:
            payload["exp"] = jwt.datetime.datetime.now(
                jwt.datetime.timezone.utc
            ) + jwt.datetime.timedelta(minutes=expiration_minutes)
            token = jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")
            return token
        except Exception as e:
            logging.error(f"Error generating token: {e}")
            raise

    @staticmethod
    def decode_token(token):
        """
        Decode a JWT token and validate its authenticity.
        :param token: Encoded JWT token.
        :return: Decoded payload.
        """
        try:
            decoded = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            return decoded
        except jwt.ExpiredSignatureError:
            logging.warning("Token has expired.")
            raise jwt.ExpiredSignatureError("Token has expired.")
        except jwt.InvalidTokenError:
            logging.warning("Invalid token.")
            raise jwt.InvalidTokenError("Invalid token.")


def token_required(f):
    """
    A decorator to enforce token-based authentication on protected routes.
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # Check if the token is in the Authorization header
        if "Authorization" in request.headers:
            auth_header = request.headers["Authorization"]
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]

        if not token:
            return jsonify({"error": "Token is missing!"}), 401

        try:
            # Decode the token and extract the user_id
            decoded = TokenManager.decode_token(token)
            user_id = decoded.get("user_id")
            if not user_id:
                return jsonify({"error": "Invalid token structure!"}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired!"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token!"}), 401

        # Pass the user_id to the wrapped function
        return f(user_id, *args, **kwargs)

    return decorated
