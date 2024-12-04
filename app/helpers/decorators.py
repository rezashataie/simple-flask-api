from functools import wraps
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
from app.models.user_model import User
from app.helpers.db_helpers import session_scope
from app.helpers.response_helpers import api_response


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        user_id = get_jwt_identity()

        with session_scope() as session:
            user = session.query(User).get(user_id)
            if not user:
                return api_response(
                    success=False,
                    message="User not found.",
                    errors={"user": "User does not exist."},
                    status_code=404,
                )
            if user.is_admin != "yes":
                return api_response(
                    success=False,
                    message="Admin access required.",
                    errors={
                        "authorization": "You do not have permission to access this resource."
                    },
                    status_code=403,
                )

        return fn(*args, **kwargs)

    return wrapper
