from app.models.base_model import BaseModel
from app import db


class Category(BaseModel):
    """
    Category model for managing category-related data.
    """

    __tablename__ = "categories"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    slug = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(50), unique=True, nullable=False)
    scores = db.Column(db.String(255), nullable=False)

    def __init__(self, slug, name, scores):
        self.slug = slug
        self.name = name
        self.scores = scores

    def __repr__(self):
        return f"<Category {self.name}>"

    def get_scores(self):
        """
        Convert the scores string to a list of integers.
        """
        return list(map(int, self.scores.split(",")))
