# Tệp: security_gate/database/session.py
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, declarative_base

# Sử dụng SQLite cho môi trường luận văn, dễ dàng mang đi báo cáo
SQLALCHEMY_DATABASE_URL = "sqlite:///./supply_chain_guard.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, 
    connect_args={"check_same_thread": False} # Bắt buộc cho FastAPI khi dùng SQLite
)

# BẬT KIỂM TRA KHÓA NGOẠI (Rất quan trọng để bảo vệ dữ liệu Multi-tenancy)
def _fk_pragma_on_connect(dbapi_con, con_record):
    dbapi_con.execute('pragma foreign_keys=ON')

event.listen(engine, 'connect', _fk_pragma_on_connect)

# Khởi tạo Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    """Dependency Injection cung cấp database session cho mỗi request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()