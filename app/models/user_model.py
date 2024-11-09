from datetime import datetime
import random
import pytz
from app import db

# Define Tehran timezone
tehran = pytz.timezone("Asia/Tehran")


def current_time_tehran():
    return datetime.now(tehran)


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    mobile = db.Column(db.String(15), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(80), nullable=True, default=None)
    family = db.Column(db.String(80), nullable=True, default=None)
    email = db.Column(db.String(120), unique=True, nullable=True, default=None)

    # New fields for account activation and password reset
    verify_code = db.Column(db.Integer, nullable=True)  # Code for account verification
    status = db.Column(db.String(10), nullable=False, default="inactive")  # Account status: "active" or "inactive"
    verify_try = db.Column(db.Integer, nullable=False, default=0)  # Number of verification attempts
    reset_code = db.Column(db.Integer, nullable=True)  # Code for password reset
    reset_try = db.Column(db.Integer, nullable=False, default=0)  # Number of password reset attempts

    # Timestamps with Tehran timezone
    created_at = db.Column(db.DateTime, default=current_time_tehran)  # Creation time in Tehran timezone
    updated_at = db.Column(db.DateTime, default=current_time_tehran, onupdate=current_time_tehran)  # Update time in Tehran timezone

    def __init__(self, mobile, password):
        self.mobile = mobile
        self.password = password
        self.verify_code = random.randint(111111, 999999)  # Generate a 6-digit random code
        self.status = "inactive"

    def __repr__(self):
        return f"<User {self.mobile}>"
