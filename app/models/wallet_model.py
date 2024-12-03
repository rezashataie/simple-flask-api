from app import db
from app.models.base_model import BaseModel
from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime
from cryptography.fernet import Fernet
import os


class Wallet(BaseModel):
    __tablename__ = "wallets"

    id = Column(Integer, primary_key=True)
    address = Column(String(255), unique=True, nullable=False)
    encrypted_private_key = Column(String(255), nullable=False)
    network = Column(String(50), nullable=False, default="Polygon")

    def set_private_key(self, private_key):
        """
        Encrypt and set the private key.
        """
        key = os.getenv("ENCRYPTION_KEY")
        f = Fernet(key)
        encrypted_key = f.encrypt(private_key.encode())
        self.encrypted_private_key = encrypted_key.decode()

    def get_private_key(self):
        """
        Decrypt and return the private key.
        """
        key = os.getenv("ENCRYPTION_KEY")
        f = Fernet(key)
        decrypted_key = f.decrypt(self.encrypted_private_key.encode())
        return decrypted_key.decode()
