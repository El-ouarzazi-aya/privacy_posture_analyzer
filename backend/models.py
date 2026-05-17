from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database import Base


class Audit(Base):
    __tablename__ = "audits"

    id              = Column(Integer, primary_key=True, index=True)
    app_id          = Column(String, unique=True, index=True, nullable=False)
    app_name        = Column(String, nullable=True)
    package_name    = Column(String, nullable=True)
    apk_size_mb     = Column(Float, nullable=True)
    created_at      = Column(DateTime(timezone=True), server_default=func.now())
    privacy_score   = Column(Integer, nullable=True)

    trackers        = relationship("Tracker", back_populates="audit")


class Tracker(Base):
    __tablename__ = "trackers"

    id              = Column(Integer, primary_key=True, index=True)
    audit_id        = Column(Integer, ForeignKey("audits.id"), nullable=False)
    sdk_name        = Column(String, nullable=False)
    category        = Column(String, nullable=False)
    risk_score      = Column(Integer, nullable=False)
    data_collected  = Column(String, nullable=True)

    audit           = relationship("Audit", back_populates="trackers")
