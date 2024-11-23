from datetime import datetime
import pytz
from app import db

tehran = pytz.timezone("Asia/Tehran")


def current_time_tehran():
    return datetime.now(tehran)


class Game(db.Model):
    __tablename__ = 'games'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, nullable=False)
    total_round = db.Column(db.Integer, nullable=False)
    current_round = db.Column(db.Integer, nullable=False, default=0)
    teams = db.Column(db.JSON, nullable=False)
    words = db.Column(db.JSON, nullable=False)
    is_finish = db.Column(db.String(3), nullable=False, default="no")
    created_at = db.Column(db.DateTime, default=current_time_tehran)
    updated_at = db.Column(db.DateTime, default=current_time_tehran, onupdate=current_time_tehran)

    def __repr__(self):
        return f"<Game {self.id}>"
