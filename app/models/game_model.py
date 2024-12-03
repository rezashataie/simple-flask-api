from app.models.base_model import BaseModel
from app import db


class Game(BaseModel):
    __tablename__ = "games"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, nullable=False)
    total_round = db.Column(db.Integer, nullable=False)
    current_round = db.Column(db.Integer, nullable=False, default=0)
    teams = db.Column(db.JSON, nullable=False)
    words = db.Column(db.JSON, nullable=False)
    is_finish = db.Column(db.String(3), nullable=False, default="no")

    def __repr__(self):
        return f"<Game {self.id}>"
