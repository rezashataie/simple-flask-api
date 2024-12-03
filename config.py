import os
from datetime import timedelta
from dotenv import load_dotenv


# Load environment variables from .env file (if exists)
load_dotenv()


class Config:
    """
    Base configuration class. Contains default settings.
    """

    DEBUG = False
    TESTING = False

    # Database configuration
    DB_USER = os.getenv("DB_USER")
    DB_PASSWORD = os.getenv("DB_PASSWORD")
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_NAME = os.getenv("DB_NAME")

    SQLALCHEMY_DATABASE_URI = (
        f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Security and JWT settings
    SECRET_KEY = os.getenv("SECRET_KEY")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", SECRET_KEY)
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(
        minutes=int(os.getenv("JWT_EXPIRATION_DELTA", 300))
    )

    # Logging
    LOG_LEVEL = os.getenv("LOG_LEVEL", "DEBUG")

    # Mail configuration
    MAIL_SERVER = os.getenv("MAIL_SERVER")
    MAIL_PORT = int(os.getenv("MAIL_PORT", 465))
    MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "False").lower() in ["true", "1"]
    MAIL_USE_SSL = os.getenv("MAIL_USE_SSL", "True").lower() in ["true", "1"]
    MAIL_USERNAME = os.getenv("MAIL_USERNAME")
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")
    MAIL_DEFAULT_SENDER = (
        os.getenv("MAIL_SENDER_NAME"),
        os.getenv("MAIL_SENDER_EMAIL"),
    )


class DevelopmentConfig(Config):
    """
    Configuration for development environment.
    """

    DEBUG = True
    SQLALCHEMY_ECHO = True  # Show SQL queries in logs


class ProductionConfig(Config):
    """
    Configuration for production environment.
    """

    DEBUG = False
    LOG_LEVEL = "INFO"


class TestingConfig(Config):
    """
    Configuration for testing environment.
    """

    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"  # In-memory database for testing


def get_config():
    """
    Returns the configuration class based on the FLASK_ENV environment variable.
    """
    env = os.getenv("FLASK_ENV", "development").lower()
    if env == "production":
        return ProductionConfig
    elif env == "testing":
        return TestingConfig
    return DevelopmentConfig
