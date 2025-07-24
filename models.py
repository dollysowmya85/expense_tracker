from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Float,
    DateTime,
    UniqueConstraint,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from flask_login import UserMixin

# 1. Configure the SQLite database file
# In models.py
engine = create_engine('sqlite:///expenses_new.db', echo=False)
Session = sessionmaker(bind=engine)
Base = declarative_base()

# 2. User model for authentication
class User(Base, UserMixin):
    __tablename__ = 'users'
    id            = Column(Integer, primary_key=True)
    username      = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)

# 3. Transaction model
class Transaction(Base):
    __tablename__ = 'transactions'
    id          = Column(Integer, primary_key=True)
    user_id     = Column(Integer, nullable=False)
    filename    = Column(String, nullable=False)
    description = Column(String, nullable=False)
    amount      = Column(Float,   nullable=False)
    timestamp   = Column(DateTime, default=datetime.utcnow)

# 4. Threshold model for alerts
class Threshold(Base):
    __tablename__ = 'thresholds'
    id        = Column(Integer, primary_key=True)
    user_id   = Column(Integer, nullable=False)
    category  = Column(String,  nullable=False)
    limit     = Column(Float,   nullable=False)
    __table_args__ = (
        UniqueConstraint('user_id', 'category', name='uq_user_category'),
    )

# 5. Create all tables
Base.metadata.create_all(engine)

