from app.models.base_model import BaseModel
from app import db


class User(BaseModel):
    """
    User model for managing user-related data.
    """

    __tablename__ = "users"

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

    def __init__(self, mobile, email, password, name, verify_code):
        self.mobile = mobile
        self.email = email
        self.password = password
        self.name = name
        self.verify_code = verify_code

    def __repr__(self):
        return f"<User {self.mobile}>"
