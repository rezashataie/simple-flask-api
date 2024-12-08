def register_routes(app):
    """
    Register all route blueprints with the Flask application instance.
    :param app: The Flask app instance.
    """
    from .auth_routes import auth_bp
    from .wallet_routes import wallet_bp
    from .contract_routes import contract_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(wallet_bp)
    app.register_blueprint(contract_bp)
