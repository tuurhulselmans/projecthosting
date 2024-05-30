from sqlalchemy import Boolean, Column, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    files_directory = Column(String, default=lambda: f"./user_files/{id}")
    token = Column(String)  # new field for the token

    vms = relationship("VM", back_populates="owner")
    websites = relationship("Website", back_populates="owner")
    websites = relationship("Website", back_populates="owner")

class VM(Base):
    __tablename__ = "vms"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    VM_id = Column(String, index=True)
    ip = Column(String, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"))

    owner = relationship("User", back_populates="vms")

class Website(Base):
    __tablename__ = "websites"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"))

    owner = relationship("User", back_populates="websites")


