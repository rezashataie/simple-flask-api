# from app import create_app, db
# from app.models.base_model import BaseModel
# from app.models.category_model import Category
# from app.models.game_model import Game
# from app.models.user_model import User
# from app.models.word_model import Word
# from app.models.wallet_model import Wallet
# from app.models.contract_wallet_model import Contract_Wallet

# app = create_app()

# with app.app_context():
#     try:
#         print("Dropping all existing tables...")
#         db.drop_all()
#         print("Existing tables dropped successfully!")

#         print("Creating new tables...")
#         db.create_all()
#         print("All tables created successfully!")
#     except Exception as e:
#         print(f"An error occurred: {e}")
