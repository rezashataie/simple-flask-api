from datetime import datetime
import pytz
from app import db

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
        try:
            db.session.add(self)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            raise e

    def delete(self):
        """
        Delete the current instance from the database.
        """
        try:
            db.session.delete(self)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            raise e
