import uvicorn
from pathlib import Path
from fastapi import FastAPI, Request, HTTPException
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

# Import Database Config
from security_gate.database.session import engine, Base

# Import Routers (Tất cả logic xử lý lõi đã được module hóa và nằm ở đây)
from security_gate.api.routes import router as api_router
from security_gate.api.ui_routes import router as ui_router

# ==========================================
# 1. MIDDLEWARE BẢO VỆ SERVER (Giới hạn Upload 5GB)
# ==========================================
class LimitUploadSizeMiddleware(BaseHTTPMiddleware):
    """
    Middleware chặn các request có kích thước vượt quá ngưỡng cho phép ngay từ đầu,
    tránh làm treo server khi xử lý file quá lớn.
    """
    def __init__(self, app, max_upload_size: int):
        super().__init__(app)
        self.max_upload_size = max_upload_size

    async def dispatch(self, request: Request, call_next):
        if request.method == "POST":
            content_length = request.headers.get('content-length')
            if content_length and int(content_length) > self.max_upload_size:
                raise HTTPException(status_code=413, detail="File quá lớn. Giới hạn upload là 5GB.")
        return await call_next(request)

# ==========================================
# 2. KHỞI TẠO HỆ THỐNG & DATABASE
# ==========================================
# Khởi tạo các thư mục thiết yếu để tránh lỗi FileNotFoundError khi chạy lần đầu
for path in ["data/uploads", "data/sbom", "data/reports", "security_gate/static"]:
    Path(path).mkdir(parents=True, exist_ok=True)

# Tạo bảng trong CSDL
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Supply Chain Guard Pro API", 
    description="Engine định lượng rủi ro chuỗi cung ứng phần mềm (chuẩn OWASP ASVS 5.0.0)", 
    version="1.0.0"
)

# ==========================================
# 3. CẤU HÌNH MIDDLEWARE (Security & CORS)
# ==========================================
# Chống lỗi CORS khi frontend gọi API từ một domain/port khác
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Bảo mật phiên đăng nhập (Session)
app.add_middleware(SessionMiddleware, secret_key="luan_van_super_secret_key_2026")

# Kích hoạt Middleware giới hạn file 5GB (5 * 1024 * 1024 * 1024 bytes)
app.add_middleware(LimitUploadSizeMiddleware, max_upload_size=5368709120)

# ==========================================
# 4. GẮN STATIC FILES VÀ ROUTERS
# ==========================================
app.mount("/static", StaticFiles(directory="security_gate/static"), name="static")

# Giao diện người dùng (Login, Workspace, Project Dashboard)
app.include_router(ui_router) 

# API Lõi (Bao gồm cả /api/v1/scan, /api/v1/export, /api/v1/cicd/scan)
app.include_router(api_router)

@app.get("/")
async def root():
    return {"message": "Hệ thống Supply Chain Guard Pro đang hoạt động ổn định."}

# ==========================================
# 5. ENTRY POINT KHỞI CHẠY SERVER
# ==========================================
if __name__ == "__main__":
    # Điểm cộng cho đồ án: Dùng host="0.0.0.0" để dễ dàng đưa lên Docker 
    # Tăng timeout_keep_alive để đường truyền không bị đứt khi upload file 5GB
    uvicorn.run(
        "main:app", 
        host="127.0.0.1", 
        port=8000, 
        reload=True,
        timeout_keep_alive=600 
    )