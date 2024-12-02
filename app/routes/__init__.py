def register_routes(app):
    """
    Register all route blueprints with the Flask application instance.
    :param app: The Flask app instance.
    """
    from .auth_routes import auth_bp

    # Register the auth blueprint
    app.register_blueprint(auth_bp)
