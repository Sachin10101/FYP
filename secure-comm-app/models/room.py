from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Table
from sqlalchemy.orm import relationship, Session
from sqlalchemy.sql import func
from typing import List, Dict
from datetime import datetime
from database import Base

# Association table for many-to-many relationship between rooms and users
room_user_association = Table(
    'room_users',
    Base.metadata,
    Column('room_id', Integer, ForeignKey('rooms.id'), primary_key=True),
    Column('user_id', Integer, ForeignKey('users.id'), primary_key=True),
    Column('joined_at', DateTime, server_default=func.now())
)

class Room(Base):
    __tablename__ = "rooms"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    created_at = Column(DateTime, server_default=func.now())
    
    # Relationships
    users = relationship("User", secondary=room_user_association, back_populates="rooms")
    messages = relationship("Message", back_populates="room")

    @staticmethod
    def create_room(db: Session, name: str) -> 'Room':
        """Create a new chat room"""
        room = Room(name=name)
        db.add(room)
        db.commit()
        db.refresh(room)
        return room

    @staticmethod
    def add_user_to_room(db: Session, room_id: int, user_id: int) -> bool:
        """Add user to a room"""
        try:
            db.execute(
                room_user_association.insert().values(room_id=room_id, user_id=user_id)
            )
            db.commit()
            return True
        except:
            db.rollback()
            return False

class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    room_id = Column(Integer, ForeignKey('rooms.id'))
    user_id = Column(Integer, ForeignKey('users.id'))
    content = Column(String)
    timestamp = Column(DateTime, server_default=func.now())

    # Relationships
    room = relationship("Room", back_populates="messages")
    user = relationship("User")

    @staticmethod
    def save_message(db: Session, room_id: int, user_id: int, content: str) -> 'Message':
        """Save a message to the database"""
        message = Message(room_id=room_id, user_id=user_id, content=content)
        db.add(message)
        db.commit()
        db.refresh(message)
        return message

    @staticmethod
    def get_room_messages(db: Session, room_id: int, limit: int = 100) -> List[Dict]:
        """Retrieve recent messages for a room"""
        messages = db.query(Message).filter(
            Message.room_id == room_id
        ).order_by(
            Message.timestamp.desc()
        ).limit(limit).all()
        
        return [
            {
                "id": msg.id,
                "room_id": msg.room_id,
                "user_id": msg.user_id,
                "content": msg.content,
                "timestamp": msg.timestamp,
                "username": msg.user.username
            }
            for msg in messages
        ]

    @staticmethod
    def get_user_rooms(db: Session, user_id: int) -> List[Dict]:
        """Get all rooms a user belongs to"""
        rooms = db.query(Room).join(
            room_user_association
        ).filter(
            room_user_association.c.user_id == user_id
        ).all()
        
        return [
            {
                "id": room.id,
                "name": room.name,
                "created_at": room.created_at
            }
            for room in rooms
        ]
        
    @staticmethod
    def is_user_in_room(db: Session, room_id: int, user_id: int) -> bool:
        """Check if a user is already in a room"""
        result = db.query(room_user_association).filter(
            room_user_association.c.room_id == room_id,
            room_user_association.c.user_id == user_id
        ).first()
        return result is not None
