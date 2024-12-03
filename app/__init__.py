from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_mail import Mail
from flask_jwt_extended import JWTManager
from config import get_config
from dotenv import load_dotenv
import logging
import os

# Load environment variables
load_dotenv()

# Initialize Flask extensions
db = SQLAlchemy()
migrate = Migrate()
mail = Mail()

# Initialize JWTManager
jwt = JWTManager()


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
    logging.info("Flask extensions initialized.")


def register_routes(app):
    """
    Register all routes with the Flask application.
    :param app: Flask app instance.
    """
    from app.routes import register_routes as routes_register

    routes_register(app)
    logging.info("Routes registered successfully.")
