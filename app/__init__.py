from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_mail import Mail
from config import Config
from dotenv import load_dotenv
import os
import logging

load_dotenv()

db = SQLAlchemy()
migrate = Migrate()
mail = Mail()


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    log_level = app.config['LOG_LEVEL']
    logging.basicConfig(level=log_level, format='%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')

    db.init_app(app)
    migrate.init_app(app, db)
    mail.init_app(app)

    from app.routes import register_routes
    register_routes(app)

    return app
