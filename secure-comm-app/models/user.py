from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import Session, relationship
from sqlalchemy.exc import IntegrityError
import bcrypt
from typing import Optional, List
from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)
    
    # Relationships
    rooms = relationship("Room", secondary="room_users", back_populates="users")


    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using bcrypt"""
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    @staticmethod
    def is_email_username_unique(db: Session, email: str, username: str) -> bool:
        """Check if email and username are available"""
        return (
            db.query(User).filter((User.username == username) | (User.email == email)).first() is None
        )

    @staticmethod
    def create_user(db: Session, email: str, username: str, password: str) -> Optional['User']:
        """Create new user with email, username, and hashed password"""
        if not User.is_email_username_unique(db, email, username):
            return None
            
        password_hash = User.hash_password(password)
        user = User(email=email, username=username, password_hash=password_hash)
        db.add(user)
        try:
            db.commit()
            db.refresh(user)
            return user
        except IntegrityError:
            db.rollback()
            return None

    @staticmethod
    def authenticate(db: Session, username: str, password: str) -> bool:
        """Verify user credentials"""
        user = db.query(User).filter(User.username == username).first()
        if not user:
            return False
            
        return bcrypt.checkpw(
            password.encode('utf-8'),
            user.password_hash.encode('utf-8')
        )
