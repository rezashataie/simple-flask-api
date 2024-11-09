import os


class Config:
    DEBUG = True

    SQLALCHEMY_DATABASE_URI = (
        f"mysql+pymysql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@{os.getenv('DB_HOST')}/{os.getenv('DB_NAME')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.getenv('SECRET_KEY')

    JWT_EXPIRATION_DELTA = int(os.getenv('JWT_EXPIRATION_DELTA'))

    LOG_LEVEL = os.getenv('LOG_LEVEL')
