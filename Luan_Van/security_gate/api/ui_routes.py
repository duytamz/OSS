# Tệp: security_gate/api/ui_routes.py
import logging
import traceback
from fastapi import APIRouter, Depends, Request, Form, status, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from typing import List
from security_gate.database.session import get_db
from security_gate.database.models import AuditLog, User, Organization, Project, ScanReport
from security_gate.schemas.users import ProjectResponseSchema
from security_gate.database.models import UserRole

router = APIRouter()
templates = Jinja2Templates(directory="security_gate/templates")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ==========================================
# 1. ROUTE TRANG CHỦ (TỰ ĐỘNG ĐIỀU HƯỚNG CẢI TIẾN)
# ==========================================
@router.get("/", response_class=HTMLResponse)
async def serve_home(request: Request, db: Session = Depends(get_db)):
    """Trang chủ tự động điều hướng thông minh."""
    user_id = request.session.get("user_id")
    
    if user_id:
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            return RedirectResponse(url="/management", status_code=status.HTTP_303_SEE_OTHER)
        else:
            request.session.clear()
            
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

# ==========================================
# 2. CÁC TRANG XÁC THỰC (AUTH)
# ==========================================
@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse(url="/management", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("login.html", {"request": request})

@router.post("/login")
async def login_action(
    request: Request, 
    email: str = Form(...), 
    password: str = Form(...), 
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.email == email).first()
    if not user or not pwd_context.verify(password, user.hashed_password):
        return templates.TemplateResponse("login.html", {
            "request": request, 
            "error": "Email hoặc mật khẩu không chính xác!"
        })
    
    request.session["user_id"] = user.id
    return RedirectResponse(url="/management", status_code=status.HTTP_303_SEE_OTHER)

@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@router.post("/register")
async def register_action(
    request: Request, 
    email: str = Form(...), 
    password: str = Form(...), 
    full_name: str = Form(...), 
    org_name: str = Form(...), 
    db: Session = Depends(get_db)
):
    if db.query(User).filter(User.email == email).first():
        return templates.TemplateResponse("register.html", {"request": request, "error": "Email đã tồn tại!"})
        
    org = db.query(Organization).filter(Organization.name == org_name).first()
    assigned_role = "member" 
    
    if not org:
        org = Organization(name=org_name)
        db.add(org)
        db.commit()
        db.refresh(org)
        assigned_role = "admin"
        
    hashed_pwd = pwd_context.hash(password)
    new_user = User(
        email=email, 
        hashed_password=hashed_pwd, 
        full_name=full_name, 
        org_id=org.id,
        role=assigned_role 
    )
    db.add(new_user)
    db.commit()
    
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

@router.get("/logout")
async def logout_action(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

# ==========================================
# 3. WORKSPACE & QUẢN LÝ DỰ ÁN
# ==========================================
@router.get("/management", response_class=HTMLResponse)
async def management_page(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id: return RedirectResponse(url="/login")
    
    user = db.query(User).filter(User.id == user_id).first()
    
    if user.role == "admin" or user.role == UserRole.ADMIN:
        projects = db.query(Project).filter(
            Project.organization_id == user.org_id, 
            Project.is_deleted == False
        ).all()
    else:
        projects = db.query(Project).filter(
            Project.owner_id == user.id, 
            Project.is_deleted == False
        ).all()
    
    return templates.TemplateResponse("management.html", {"request": request, "user": user, "projects": projects})

@router.post("/create_project")
async def create_project(request: Request, project_name: str = Form(...), db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    user = db.query(User).filter(User.id == user_id).first()
    
    new_proj = Project(
        name=project_name, 
        description="Dự án đánh giá ASVS 5.0", 
        organization_id=user.org_id, 
        owner_id=user.id,
        creator_id=user.id 
    )
    db.add(new_proj)
    db.commit()
    db.refresh(new_proj)
    
    log = AuditLog(user_id=user.id, action="CREATE_PROJECT", target_type="PROJECT", target_id=new_proj.id, details=f"Tạo dự án: {project_name}")
    db.add(log)
    db.commit()
    
    return RedirectResponse(url="/management", status_code=status.HTTP_303_SEE_OTHER)

@router.post("/delete_project/{project_id}")
async def delete_project(request: Request, project_id: int, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id: return RedirectResponse(url="/login")
    user = db.query(User).filter(User.id == user_id).first()
    
    project = db.query(Project).filter(Project.id == project_id, Project.is_deleted == False).first()
    
    if not project:
        return HTMLResponse("<h2 style='color:red;'>Dự án không tồn tại hoặc đã bị xóa.</h2>", status_code=404)
        
    if project.owner_id != user.id and user.role not in ["admin", UserRole.ADMIN]:
        return HTMLResponse("<h2 style='color:red;'>🚫 403: Bạn không có quyền xóa dự án của người khác.</h2>", status_code=403)
    
    project.is_deleted = True
    
    log = AuditLog(user_id=user.id, action="SOFT_DELETE_PROJECT", target_type="PROJECT", target_id=project.id, details=f"Xóa mềm dự án: {project.name}")
    db.add(log)
    db.commit()
        
    return RedirectResponse(url="/management", status_code=status.HTTP_303_SEE_OTHER)

# ==========================================
# 4. CHỨC NĂNG LÕI: QUÉT MÃ & LỊCH SỬ (ĐÃ VÁ IDOR CHO TC-05)
# ==========================================
@router.get("/project/{project_id}", response_class=HTMLResponse)
async def project_scan_page(request: Request, project_id: int, db: Session = Depends(get_db)):
    """Trang giao diện Quét mã nguồn - Đã tích hợp chống xem trộm."""
    user_id = request.session.get("user_id")
    if not user_id: 
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user: return RedirectResponse(url="/login")
    
    # Chỉ lấy dự án chưa bị xóa
    project = db.query(Project).filter(Project.id == project_id, Project.is_deleted == False).first()
    if not project:
        return RedirectResponse(url="/management", status_code=status.HTTP_303_SEE_OTHER)

    # ---------------------------------------------------------
    # BẮT ĐẦU VÁ LỖI IDOR (ĐÁP ỨNG KỊCH BẢN TC-05)
    # ---------------------------------------------------------
    if user.role in ["admin", UserRole.ADMIN]:
        if project.organization_id != user.org_id:
            # Admin nhưng lấn sân sang công ty khác -> Kick về trang quản lý
            return RedirectResponse(url="/management?error=idor_blocked", status_code=status.HTTP_303_SEE_OTHER)
    else:
        # Member thường truy cập dự án của người khác -> Kick về trang quản lý
        if project.owner_id != user.id and project.creator_id != user.id:
            return RedirectResponse(url="/management?error=idor_blocked", status_code=status.HTTP_303_SEE_OTHER)
    # ---------------------------------------------------------
        
    return templates.TemplateResponse("index.html", {
        "request": request, 
        "user": user,       
        "project": project
    })

@router.get("/project/{project_id}/history", response_class=HTMLResponse)
async def project_history_page(request: Request, project_id: int, db: Session = Depends(get_db)):
    """Trang giao diện xem Lịch sử Audit - Đã tích hợp chống xem trộm."""
    try:
        user_id = request.session.get("user_id")
        if not user_id:
            return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
            
        current_user = db.query(User).filter(User.id == user_id).first()
        if not current_user:
            return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

        project = db.query(Project).filter(Project.id == project_id, Project.is_deleted == False).first()
        if not project:
            return RedirectResponse(url="/management", status_code=status.HTTP_303_SEE_OTHER)
            
        # ---------------------------------------------------------
        # BẮT ĐẦU VÁ LỖI IDOR CHO LỊCH SỬ (TC-05)
        # ---------------------------------------------------------
        if current_user.role in ["admin", UserRole.ADMIN]:
            if project.organization_id != current_user.org_id:
                return RedirectResponse(url="/management?error=idor_blocked", status_code=status.HTTP_303_SEE_OTHER)
        else:
            if project.owner_id != current_user.id and project.creator_id != current_user.id:
                return RedirectResponse(url="/management?error=idor_blocked", status_code=status.HTTP_303_SEE_OTHER)
        # ---------------------------------------------------------
            
        scan_history = db.query(ScanReport).filter(ScanReport.project_id == project_id).filter(ScanReport.is_deleted == False).order_by(ScanReport.scan_date.desc()).all()
        
        return templates.TemplateResponse("history.html", {
            "request": request, 
            "project": project, 
            "scan_history": scan_history,
            "user": current_user
        })
        
    except Exception as e:
        error_trace = traceback.format_exc()
        logging.error(f"CRITICAL ERROR in /history: \n{error_trace}")
        return HTMLResponse(
            content=f"<h2>Lỗi Backend: {str(e)}</h2><pre>{error_trace}</pre>", 
            status_code=500
        )

@router.post("/delete_report/{report_id}")
async def delete_report(request: Request, report_id: int, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id: return RedirectResponse(url="/login")
    
    user = db.query(User).filter(User.id == user_id).first()
    
    report = db.query(ScanReport).join(Project).filter(
        ScanReport.id == report_id,
        ScanReport.is_deleted == False
    ).first()
    
    if report:
        # VÁ IDOR: Kiểm tra quyền sở hữu project chứa report này
        project = db.query(Project).filter(Project.id == report.project_id).first()
        if user.role not in ["admin", UserRole.ADMIN] and project.owner_id != user.id:
             return HTMLResponse("Không đủ quyền xóa báo cáo này.", status_code=403)
             
        report.is_deleted = True
        
        log = AuditLog(user_id=user.id, action="SOFT_DELETE_REPORT", target_type="REPORT", target_id=report.id, details="Xóa mềm báo cáo")
        db.add(log)
        db.commit()
        
        return RedirectResponse(url=f"/project/{project.id}/history", status_code=status.HTTP_303_SEE_OTHER)
        
    return HTMLResponse("Không tìm thấy báo cáo", status_code=404)

@router.get("/api/organizations/projects", response_model=List[ProjectResponseSchema])
async def get_organization_projects(
    request: Request,
    db: Session = Depends(get_db)
):
    user_id = request.session.get("user_id")
    if not user_id: 
        raise HTTPException(status_code=401, detail="Chưa đăng nhập")
        
    current_user = db.query(User).filter(User.id == user_id).first()
    
    if current_user.role not in ["admin", UserRole.ADMIN]: 
        raise HTTPException(status_code=403, detail="Yêu cầu quyền Admin")

    projects = db.query(Project).filter(
        Project.organization_id == current_user.org_id,
        Project.is_deleted == False
    ).all()
    
    return projects