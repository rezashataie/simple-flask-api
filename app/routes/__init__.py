def register_routes(app):
    # Import individual route blueprints
    from .auth_routes import auth_bp

    # Register the blueprints with the app
    app.register_blueprint(auth_bp)
