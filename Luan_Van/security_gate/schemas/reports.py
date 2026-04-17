from pydantic import BaseModel, Field, ConfigDict
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum

# ==========================================
# 1. ENUMS (Định nghĩa các hằng số chuẩn hóa theo báo cáo)
# ==========================================
class DecisionEnum(str, Enum):
    """Ngưỡng phân vùng thực thi theo Chương 3.5 & Cơ chế Human-in-the-Loop"""
    APPROVED = "APPROVED"          # R >= 8.0 (Vùng Xanh - Đủ điều kiện tự động duyệt)
    PENDING = "PENDING"            # 5.0 <= R < 8.0 (Vùng Vàng - Cảnh báo, cần xem xét)
    REJECTED = "REJECTED"          # R < 5.0 (Vùng Đỏ - Chặn cứng pipeline)
    PENDING_REVIEW = "PENDING_REVIEW" # (VÁ LỖI) Vùng Cam - Điểm R >= 8.0 nhưng bị mù dữ liệu mạng, tước quyền tự động duyệt

class ASVSRequirement(str, Enum):
    """Ma trận ánh xạ ASVS 5.0.0 (Bảng 3.1)"""
    V1_1_1 = "V1.1.1"   # Xác minh danh sách thành phần (SBOM)
    V1_14_2 = "V1.14.2" # Kiểm tra lỗ hổng đã biết (CVE)
    V10_2_1 = "V10.2.1" # Phát hiện mã độc/hành vi RCE
    V14_2_3 = "V14.2.3" # Xác minh chữ ký số & tính toàn vẹn

class EvidenceStatus(str, Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    INDETERMINATE = "INDETERMINATE"

# ==========================================
# 2. SCHEMAS CHO EVIDENCE JSON MODEL (Theo mục 3.2)
# ==========================================
class AssessmentMetadata(BaseModel):
    asvs_version: str = Field(default="5.0.0", description="Phiên bản ASVS áp dụng")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    target_component: str = Field(..., description="Tên và phiên bản thư viện/artifact")

class TechnicalEvidence(BaseModel):
    tool: str = Field(..., description="Công cụ phân tích (VD: OSV-Scanner, Syft, Yara)")
    raw_data: Dict[str, Any] = Field(..., description="Dữ liệu thô trả về từ công cụ")
    extracted_variables: Dict[str, Any] = Field(..., description="Các biến số kỹ thuật được trích xuất (VD: max_cvss, is_exploitable)")

class MappingResult(BaseModel):
    requirement_id: ASVSRequirement
    status: EvidenceStatus
    technical_evidence: TechnicalEvidence
    quantitative_score: float = Field(ge=0, le=10, description="Điểm số chuẩn hóa Ci (1-10)")

class EvidenceJSONModel(BaseModel):
    """Cấu trúc dữ liệu đầu ra chuẩn hóa phục vụ kiểm toán (Mục 3.2)"""
    assessment_metadata: AssessmentMetadata
    mapping_results: List[MappingResult]

# ==========================================
# 3. SCHEMAS CHO RISK SCORING MODEL (RSM)
# ==========================================
class ComponentScores(BaseModel):
    """Điểm số chuẩn hóa cho 4 tiêu chí cốt lõi (Bảng 3.2)"""
    cv: float = Field(ge=0, le=10, description="Vulnerability - Trọng số 0.45")
    ci: float = Field(ge=0, le=10, description="Integrity - Trọng số 0.20")
    cm: float = Field(ge=0, le=10, description="Maintenance - Trọng số 0.25")
    cl: float = Field(ge=0, le=10, description="License - Trọng số 0.10")

class ComponentEvaluation(BaseModel):
    """Đánh giá chi tiết cho từng thư viện con"""
    name: str
    version: str
    c_scores: ComponentScores
    r_score: float = Field(ge=0, le=10, description="Điểm rủi ro tổng hợp R")

# ==========================================
# 4. SCHEMA ĐẦU RA CHO API BÁO CÁO (Giai đoạn 4)
# ==========================================
class ScanReportResponse(BaseModel):
    """Báo cáo trả về cho UI và CI/CD Pipeline"""
    report_id: int
    artifact_name: str
    hash_sha256: str
    
    final_score: float = Field(ge=0, le=10, description="Chỉ số rủi ro tổng quát R")
    decision: DecisionEnum = Field(..., description="Quyết định thực thi")
    weakest_link: Optional[str] = Field(None, description="Thành phần yếu nhất")
    
    # BỘ ĐIỂM SỐ ĐỂ VẼ BIỂU ĐỒ RADAR TRÊN UI
    scores: Dict[str, float] = Field(default_factory=dict, description="Bộ điểm số thành phần (CV, CI, CM, CL)")
    
    components_detail: List[ComponentEvaluation] = []
    evidence_audit: Optional[EvidenceJSONModel] = None

    # Tích hợp model_config cho Pydantic V2 (thay thế cho Config orm_mode cũ)
    model_config = ConfigDict(from_attributes=True)