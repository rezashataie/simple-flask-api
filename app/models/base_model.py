from datetime import datetime
import pytz
from app import db
from app.helpers.db_helpers import session_scope

tehran = pytz.timezone("Asia/Tehran")


def current_time_tehran():
    """
    Return the current time in Tehran timezone.
    """
    return datetime.now(tehran)


class BaseModel(db.Model):
    """
    Base model to include common fields and methods for all models.
    """

    __abstract__ = True

    created_at = db.Column(db.DateTime, default=current_time_tehran)
    updated_at = db.Column(
        db.DateTime, default=current_time_tehran, onupdate=current_time_tehran
    )

    def save(self):
        """
        Save the current instance to the database.
        """
        with session_scope() as session:
            session.add(self)

    def delete(self):
        """
        Delete the current instance from the database.
        """
        with session_scope() as session:
            session.delete(self)
