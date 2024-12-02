from app.models.base_model import BaseModel
from app import db


class Word(BaseModel):
    """
    Word model for managing word-related data.
    """

    __tablename__ = "words"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    word = db.Column(db.String(255), nullable=False)
    cat_slug = db.Column(db.String(50), nullable=False)
    cat_title = db.Column(db.String(50), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    is_show = db.Column(db.String(10), nullable=False, default="yes")

    def __init__(self, word, cat_slug, cat_title, score, is_show):
        self.word = word
        self.cat_slug = cat_slug
        self.cat_title = cat_title
        self.score = score
        self.is_show = is_show

    def __repr__(self):
        return f"<Word {self.word}>"
