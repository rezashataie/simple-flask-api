from datetime import datetime
import pytz
from app import db

tehran = pytz.timezone("Asia/Tehran")


def current_time_tehran():
    return datetime.now(tehran)


class Category(db.Model):
    __tablename__ = 'categories'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    slug = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(50), unique=True, nullable=False)
    scores = db.Column(db.String(255), nullable=False)

    created_at = db.Column(db.DateTime, default=current_time_tehran)
    updated_at = db.Column(db.DateTime, default=current_time_tehran, onupdate=current_time_tehran)

    def __init__(self, slug, name, scores):
        self.slug = slug
        self.name = name
        self.scores = scores

    def __repr__(self):
        return f"<Category {self.name}>"

    def get_scores(self):
        return list(map(int, self.scores.split(',')))
