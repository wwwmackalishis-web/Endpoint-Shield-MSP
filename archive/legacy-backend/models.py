from sqlalchemy import Column, Integer, String, DateTime
from database import Base


class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True)
    hostname = Column(String, unique=True)
    ip_address = Column(String)
    status = Column(String)
    last_seen = Column(DateTime)


class Threat(Base):
    __tablename__ = "threats"

    id = Column(Integer, primary_key=True)
    file_hash = Column(String)
    threat_type = Column(String)
    severity = Column(String)


class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(Integer, primary_key=True)
    name = Column(String)


class Command(Base):
    __tablename__ = "commands"

    id = Column(Integer, primary_key=True)
    hostname = Column(String)
    command = Column(String)
    created_at = Column(DateTime)