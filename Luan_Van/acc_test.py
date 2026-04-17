import sys
from sqlalchemy.orm import Session
from passlib.context import CryptContext

from security_gate.database.session import SessionLocal
from security_gate.database.models import User, Organization, Project

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def seed_test_data():
    db: Session = SessionLocal()
    try:
        print("Bắt đầu khởi tạo dữ liệu kiểm thử Phân quyền (RBAC & Multi-tenancy)...")

        # ==========================================
        # 1. TẠO TỔ CHỨC (ORGANIZATIONS)
        # ==========================================
        org_a = db.query(Organization).filter(Organization.name == "Công ty A").first()
        if not org_a:
            org_a = Organization(name="Công ty A")
            db.add(org_a)
            
        org_b = db.query(Organization).filter(Organization.name == "Công ty B (Đối thủ)").first()
        if not org_b:
            org_b = Organization(name="Công ty B (Đối thủ)")
            db.add(org_b)
            
        db.commit()
        db.refresh(org_a)
        db.refresh(org_b)

        # ==========================================
        # 2. TẠO NGƯỜI DÙNG (USERS)
        # ==========================================
        users_data = [
            {"email": "admin@congty-a.com", "name": "Admin Công ty A", "role": "admin", "org_id": org_a.id},
            {"email": "dev1@congty-a.com", "name": "Lập trình viên 1 (A)", "role": "user", "org_id": org_a.id},
            {"email": "hacker@congty-b.com", "name": "Kẻ tò mò (Công ty B)", "role": "user", "org_id": org_b.id}
        ]

        created_users = {}
        for u in users_data:
            user_obj = db.query(User).filter(User.email == u["email"]).first()
            if not user_obj:
                user_obj = User(
                    email=u["email"],
                    full_name=u["name"],
                    hashed_password=get_password_hash("Test@123"),
                    is_active=True,
                    role=u["role"],
                    org_id=u["org_id"] # CHÚ Ý: Cột của User là org_id
                )
                db.add(user_obj)
                db.commit()
                db.refresh(user_obj)
            created_users[u["email"]] = user_obj

        # ==========================================
        # 3. TẠO DỰ ÁN MẪU ĐỂ TEST
        # ==========================================
        # Admin A tạo dự án
        if not db.query(Project).filter(Project.name == "Core Banking API").first():
            p1 = Project(name="Core Banking API", description="Dự án quan trọng của Công ty A", organization_id=org_a.id, owner_id=created_users["admin@congt_a.com"].id)
            db.add(p1)
            
        # Dev 1 (Công ty A) tạo dự án
        if not db.query(Project).filter(Project.name == "Frontend Portal").first():
            p2 = Project(name="Frontend Portal", description="Dự án do Dev 1 làm", organization_id=org_a.id, owner_id=created_users["dev1@congt_a.com"].id)
            db.add(p2)

        # Công ty B tạo dự án
        if not db.query(Project).filter(Project.name == "Dự án mật Công ty B").first():
            p3 = Project(name="Dự án mật Công ty B", description="Dữ liệu này tuyệt đối Công ty A không được thấy", organization_id=org_b.id, owner_id=created_users["hacker@congt_b.com"].id)
            db.add(p3)

        db.commit()

        print("\n✅ ĐÃ TẠO DỮ LIỆU THÀNH CÔNG! Hãy dùng các tài khoản sau để test:")
        print("-" * 60)
        print("1. [ADMIN CÔNG TY A] - Thấy được cả 2 dự án của Công ty A (Core Banking & Frontend Portal), nhưng không thấy của Công ty B.")
        print("   Email: admin@congty-a.com  | Pass: Test@123")
        print("-" * 60)
        print("2. [USER CÔNG TY A] - CHỈ thấy dự án do mình tạo (Frontend Portal). Không thấy dự án của Admin.")
        print("   Email: dev1@congty-a.com   | Pass: Test@123")
        print("-" * 60)
        print("3. [NGƯỜI DÙNG CÔNG TY B] - Kiểm tra cách ly Tenant (IDOR).")
        print("   Email: hacker@congty-b.com | Pass: Test@123")
        print("-" * 60)

    except Exception as e:
        db.rollback()
        print(f"❌ Có lỗi xảy ra: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    seed_test_data()