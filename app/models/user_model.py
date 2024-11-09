from app import db


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    mobile = db.Column(db.String(15), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(80), nullable=True, default=None)
    family = db.Column(db.String(80), nullable=True, default=None)
    email = db.Column(db.String(120), unique=True, nullable=True, default=None)

    def __init__(self, mobile, password, name=None, family=None, email=None):
        self.mobile = mobile
        self.password = password
        self.name = name
        self.family = family
        self.email = email

    def __repr__(self):
        return f"<User {self.mobile}>"