from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_mail import Mail
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from config import get_config
from dotenv import load_dotenv
import logging


# Load environment variables
load_dotenv()

# Initialize Flask extensions
db = SQLAlchemy()
migrate = Migrate()
mail = Mail()
jwt = JWTManager()
limiter = Limiter(key_func=get_remote_address)


def create_app():
    """
    Factory function to create and configure the Flask app instance.
    :return: Configured Flask app instance.
    """
    # Create Flask app
    app = Flask(__name__)
    app.config.from_object(get_config())
    # Set up logging
    setup_logging(app)

    # Initialize extensions
    initialize_extensions(app)

    # Register error handlers
    register_error_handlers(app)

    # Register routes
    register_routes(app)

    return app


def setup_logging(app):
    """
    Set up logging for the Flask application.
    :param app: Flask app instance.
    """
    log_level = app.config.get("LOG_LEVEL", "DEBUG")
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]",
    )
    logging.info("Logging is configured.")


def initialize_extensions(app):
    """
    Initialize Flask extensions with the app instance.
    :param app: Flask app instance.
    """
    db.init_app(app)
    migrate.init_app(app, db)
    mail.init_app(app)
    jwt.init_app(app)
    limiter.init_app(app)
    logging.info("Flask extensions initialized.")


def register_routes(app):
    """
    Register all routes with the Flask application.
    :param app: Flask app instance.
    """
    from app.routes import register_routes as routes_register

    routes_register(app)
    logging.info("Routes registered successfully.")


def register_error_handlers(app):
    """
    Register custom error handlers.
    """
    from flask_limiter.errors import RateLimitExceeded

    @app.errorhandler(RateLimitExceeded)
    def handle_rate_limit_exceeded(e):
        return (
            jsonify(
                {
                    "error": "You have exceeded your request rate limit.",
                    "message": str(e),
                }
            ),
            429,
        )
