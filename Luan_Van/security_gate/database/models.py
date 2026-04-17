from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Boolean, JSON, Text, Enum
from sqlalchemy.orm import relationship
from .session import Base
from sqlalchemy.sql import func
import enum

class UserRole(str, enum.Enum):
    ADMIN = "admin"
    MEMBER = "member"

# ==========================================
# PHẦN 1: QUẢN LÝ NGƯỜI DÙNG & ĐA KHÁCH HÀNG (MULTI-TENANCY)
# ==========================================

class Organization(Base):
    """Đại diện cho một Khách hàng/Công ty (Tenant)."""
    __tablename__ = "organizations"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    created_at = Column(DateTime, server_default=func.now())
    
    users = relationship("User", back_populates="organization")
    projects = relationship("Project", back_populates="organization")

class User(Base):
    """Đại diện cho tài khoản đăng nhập vào hệ thống."""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    full_name = Column(String)
    is_active = Column(Boolean, default=True)
    role = Column(Enum(UserRole), default=UserRole.MEMBER)
    
    org_id = Column(Integer, ForeignKey("organizations.id"), index=True)
    organization = relationship("Organization", back_populates="users")

    # Chỉ định rõ foreign_keys bằng chuỗi để tránh lỗi Circular Dependency
    projects_created = relationship(
        "Project", 
        back_populates="creator",
        foreign_keys="[Project.creator_id]" 
    )

class Project(Base):
    __tablename__ = "projects"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    description = Column(String)
    organization_id = Column(Integer, ForeignKey("organizations.id"), index=True)
    
    owner_id = Column(Integer, ForeignKey("users.id"), index=True)
    creator_id = Column(Integer, ForeignKey("users.id")) # Đã xóa phần khai báo trùng lặp
    is_deleted = Column(Boolean, default=False) 
    created_at = Column(DateTime, server_default=func.now())
    
    organization = relationship("Organization", back_populates="projects")
    owner = relationship("User", foreign_keys=[owner_id])
    creator = relationship("User", foreign_keys=[creator_id], back_populates="projects_created")
    scan_reports = relationship("ScanReport", back_populates="project")

# ==========================================
# PHẦN 2: BÁO CÁO QUÉT & AUDIT LOG
# ==========================================

class ScanReport(Base):
    __tablename__ = "scan_reports"
    
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), index=True)
    artifact_name = Column(String)
    hash_sha256 = Column(String)
    score_cv = Column(Integer)
    score_cm = Column(Integer)
    score_ci = Column(Integer)
    score_cl = Column(Integer)
    final_score = Column(Integer)
    decision = Column(String)
    scan_date = Column(DateTime, server_default=func.now())
    is_deleted = Column(Boolean, default=False)
    
    project = relationship("Project", back_populates="scan_reports")

class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    action = Column(String)
    target_type = Column(String) 
    target_id = Column(Integer)
    details = Column(Text) 
    created_at = Column(DateTime, server_default=func.now())
    
    user = relationship("User")