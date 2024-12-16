from app import db
from app.models.base_model import BaseModel
from sqlalchemy import Boolean, Column, Integer, String


class Contract_Wallet(BaseModel):
    __tablename__ = "contract_wallets"

    id = Column(Integer, primary_key=True)
    address = Column(String(255), unique=True, nullable=False)
    is_active = Column(Boolean, default=False, nullable=False) 


    def __init__(self, address, is_active):
        self.address = address
        self.is_active = is_active

    def __repr__(self):
        return f"<User {self.address}>"
