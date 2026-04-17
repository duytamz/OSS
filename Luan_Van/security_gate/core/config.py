import os
from pathlib import Path
from dotenv import load_dotenv

# 1. NHẬN DIỆN THƯ MỤC ĐỘNG (Dynamic Path Resolution)
# Tính toán tự động thư mục gốc Luan_Van (đi lùi 3 cấp từ core/config.py)
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Load file .env duy nhất ở thư mục gốc (E:\Luan_Van\.env)
load_dotenv(BASE_DIR / ".env")

class Settings:
    """Class quản lý toàn bộ cấu hình hệ thống tập trung."""
    
    PROJECT_NAME: str = "Supply Chain Guard Pro"
    VERSION: str = "1.0.0"

    # --- ĐƯỜNG DẪN HỆ THỐNG AN TOÀN ---
    DATA_DIR = BASE_DIR / "data"
    INPUT_DIR = DATA_DIR / "uploads"
    EXTRACTED_DIR = DATA_DIR / "extracted"
    SBOM_DIR = DATA_DIR / "sbom"
    REPORT_DIR = DATA_DIR / "reports"

    # --- API KEYS & SECRETS ---
    # Sử dụng os.getenv an toàn, luôn có fallback (giá trị mặc định)
    VT_API_KEY: str = os.getenv("VT_API_KEY", "")
    PIPELINE_SECRET_KEY: str = os.getenv("PIPELINE_SECRET_KEY", "default_secret_key")

    # --- CẤU HÌNH MA TRẬN AHP MẶC ĐỊNH ---
    # Chỉ lưu các hằng số tỷ lệ tại đây (Vulnerability, Maintenance, Integrity, License)
    # 0.45, 0.25, 0.20, 0.10
    AHP_MATRIX_RATIOS = [
        [0.45/0.45,  0.45/0.25,  0.45/0.20,  0.45/0.10],  # CV
        [0.25/0.45,  0.25/0.25,  0.25/0.20,  0.25/0.10],  # CM
        [0.20/0.45,  0.20/0.25,  0.20/0.20,  0.20/0.10],  # CI
        [0.10/0.45,  0.10/0.25,  0.10/0.20,  0.10/0.10]   # CL
    ]

# Khởi tạo Singleton cho Settings
settings = Settings()

# 2. KHỞI TẠO THƯ MỤC TỰ ĐỘNG (Safely create directories)
def init_directories():
    for _dir in [settings.INPUT_DIR, settings.EXTRACTED_DIR, settings.SBOM_DIR, settings.REPORT_DIR]:
        _dir.mkdir(parents=True, exist_ok=True)

# Chạy ngay khi config được import
init_directories()