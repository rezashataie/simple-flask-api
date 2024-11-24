from datetime import datetime
import random
import pytz
from app import db

tehran = pytz.timezone("Asia/Tehran")


def current_time_tehran():
    return datetime.now(tehran)


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    mobile = db.Column(db.String(15), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True, default=None)
    is_admin = db.Column(db.String(10), nullable=False, default="no")
    verify_code = db.Column(db.Integer, nullable=True)
    status = db.Column(db.String(10), nullable=False, default="inactive")
    verify_try = db.Column(db.Integer, nullable=False, default=0)
    reset_code = db.Column(db.Integer, nullable=True)
    reset_try = db.Column(db.Integer, nullable=False, default=0)

    created_at = db.Column(db.DateTime, default=current_time_tehran)
    updated_at = db.Column(db.DateTime, default=current_time_tehran, onupdate=current_time_tehran)

    def __init__(self, mobile, password):
        self.mobile = mobile
        self.password = password
        self.verify_code = random.randint(111111, 999999)
        self.status = "inactive"

    def __repr__(self):
        return f"<User {self.mobile}>"
