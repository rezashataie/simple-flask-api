import os


class Config:
    DEBUG = True

    SQLALCHEMY_DATABASE_URI = (
        f"mysql+pymysql://{os.getenv('DB_USER', 'root')}:{os.getenv('DB_PASSWORD', '')}@{os.getenv('DB_HOST', 'localhost')}/{os.getenv('DB_NAME', 'flask')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.getenv('SECRET_KEY', 'u5sg3i37cegao8bptj9wd6ibezhdvvss6elzpitf2s6mzphi1ofg2f7s0ygv1kvm')

    JWT_EXPIRATION_DELTA = int(os.getenv('JWT_EXPIRATION_DELTA', 60))
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'DEBUG')
