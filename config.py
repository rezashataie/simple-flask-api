import os


class Config:
    """
    Base configuration class. Contains default settings.
    """

    DEBUG = False
    TESTING = False

    # Database configuration
    SQLALCHEMY_DATABASE_URI = (
        f"mysql+pymysql://{os.getenv('DB_USER', 'root')}:"
        f"{os.getenv('DB_PASSWORD', '')}@"
        f"{os.getenv('DB_HOST', 'localhost')}/"
        f"{os.getenv('DB_NAME', 'flask')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Security and JWT settings
    SECRET_KEY = os.getenv(
        "SECRET_KEY", "u5sg3i37cegao8bptj9wd6ibezhdvvss6elzpitf2s6mzphi1ofg2f7s0ygv1kvm"
    )
    JWT_EXPIRATION_DELTA = int(os.getenv("JWT_EXPIRATION_DELTA", 60))

    # Logging
    LOG_LEVEL = os.getenv("LOG_LEVEL", "DEBUG")

    # Mail configuration
    MAIL_SERVER = os.getenv("MAIL_SERVER", "mail.pan2mim.ir")
    MAIL_PORT = int(os.getenv("MAIL_PORT", 465))
    MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "False").lower() in ["true", "1"]
    MAIL_USE_SSL = os.getenv("MAIL_USE_SSL", "True").lower() in ["true", "1"]
    MAIL_USERNAME = os.getenv("MAIL_USERNAME", "info@pan2mim.ir")
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "P@ssw0rd14!")
    MAIL_DEFAULT_SENDER = (
        os.getenv("MAIL_SENDER_NAME", "Pan2mim"),
        os.getenv("MAIL_SENDER_EMAIL", "info@pan2mim.ir"),
    )


class DevelopmentConfig(Config):
    """
    Configuration for development environment.
    """

    DEBUG = True


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
