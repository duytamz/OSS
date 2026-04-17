import os
import uuid
import json
import shutil
import logging
import traceback
import numpy as np
from pathlib import Path
from fastapi import APIRouter, UploadFile, File, Form, Depends, Header, HTTPException, status, Query
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

# Import Database & Models
from security_gate.database.session import get_db
from security_gate.database.models import ScanReport, Project

# Import Core & Modules
from security_gate.core.risk_engine import RiskEngine
from security_gate.modules.ingestion import IngestionModule
from security_gate.modules.analysis import AnalysisModule
from security_gate.modules.exporter import ReportExporter
from security_gate.core.config import settings
from security_gate.schemas.reports import ScanReportResponse

logger = logging.getLogger(__name__)
router = APIRouter()

# KHỞI TẠO SINGLETON
engine = RiskEngine()
ingestion_module = IngestionModule()
analysis_module = AnalysisModule(engine)
exporter_module = ReportExporter(engine)

UPLOAD_DIR = settings.INPUT_DIR
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

def get_secure_temp_path(filename: str, prefix: str = "scan_") -> Path:
    """
    [SỬA LỖI NGHIÊM TRỌNG]: Khắc phục lỗi mất đuôi kép (.tar.gz, .tar.bz2)
    Bằng cách giữ lại toàn bộ tên file gốc đã được làm sạch thay vì chỉ lấy .suffix
    """
    safe_name = "".join(c for c in filename if c.isalnum() or c in " ._-").strip()
    if not safe_name:
        safe_name = "artifact.bin"
    unique_id = uuid.uuid4().hex[:8]
    return UPLOAD_DIR / f"{prefix}{unique_id}_{safe_name}"

def sanitize_for_json(obj):
    if isinstance(obj, dict):
        return {k: sanitize_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [sanitize_for_json(v) for v in obj]
    elif isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.bool_):
        return bool(obj)
    elif isinstance(obj, np.ndarray):
        return sanitize_for_json(obj.tolist())
    return obj

# ==========================================
# 1. API QUÉT TỪ GIAO DIỆN WEB (MANUAL SCAN)
# ==========================================
@router.post("/api/v1/scan", response_model=ScanReportResponse)
async def scan_artifact(
    file: UploadFile = File(...),
    project_id: int = Form(...),
    db: Session = Depends(get_db)
):
    file_path = get_secure_temp_path(file.filename, prefix="manual_")
    
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    try:
        ingestion_data = ingestion_module.process_artifact(str(file_path))
        analysis_result = analysis_module.analyze(ingestion_data)
        clean_analysis_result = sanitize_for_json(analysis_result)

        # [SỬA LỖI UX]: Ghi đè tên file tạm bằng tên gốc của người dùng
        original_filename = file.filename
        clean_analysis_result['artifact'] = original_filename 

        # [KIẾN TRÚC MỚI]: Bắt tín hiệu "Điểm mù dữ liệu" từ Analysis Module
        has_blind_spot = any(comp.get("is_blind_spot", False) for comp in clean_analysis_result.get("details", []))

        final_score = float(clean_analysis_result.get('final_score', 0.0))
        
        # [PHÁN QUYẾT HUMAN-IN-THE-LOOP]
        if final_score >= 8.0:
            if has_blind_spot:
                decision = "PENDING_REVIEW" # Rớt mạng & Thiếu dữ liệu -> Tước quyền duyệt tự động
            else:
                decision = "APPROVED"
        elif final_score >= 5.0:
            decision = "PENDING"
        else:
            decision = "REJECTED"

        # Lưu thông tin vào Database
        new_report = ScanReport(
            project_id=project_id,
            artifact_name=original_filename, 
            hash_sha256=clean_analysis_result.get('hash', ''),
            score_cv=float(clean_analysis_result['weakest_link']['scores'].get('CV', 0)),
            score_cm=float(clean_analysis_result['weakest_link']['scores'].get('CM', 0)),
            score_ci=float(clean_analysis_result['weakest_link']['scores'].get('CI', 0)),
            score_cl=float(clean_analysis_result['weakest_link']['scores'].get('CL', 0)),
            final_score=final_score,
            decision=decision
        )
        db.add(new_report)
        db.commit()
        db.refresh(new_report)

        report_blob_path = settings.REPORT_DIR / f"full_audit_{new_report.id}.json"
        with open(report_blob_path, "w", encoding="utf-8") as f:
            json.dump(clean_analysis_result, f, ensure_ascii=False, indent=4)

        weakest_component_name = "Không xác định"
        weakest_scores = {'CV': 0, 'CI': 0, 'CM': 0, 'CL': 0} 
        
        weakest_data = clean_analysis_result.get('weakest_link')
        if isinstance(weakest_data, dict):
            weakest_component_name = weakest_data.get('name', 'Không xác định')
            weakest_scores = weakest_data.get('scores', weakest_scores)
        elif isinstance(weakest_data, str):
            weakest_component_name = weakest_data

        return {
            "report_id": new_report.id,
            "artifact_name": new_report.artifact_name,
            "hash_sha256": new_report.hash_sha256,
            "final_score": new_report.final_score,
            "decision": new_report.decision,
            "weakest_link": weakest_component_name,
            "scores": weakest_scores 
        }

    except Exception as e:
        logger.error(f"Lỗi hệ thống khi quét Manual: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="Lỗi trong quá trình phân tích mã nguồn.")

    finally:
        if file_path.exists():
            file_path.unlink()
        if 'ingestion_data' in locals() and 'extract_path' in ingestion_data:
            ingestion_module.cleanup_artifact(ingestion_data['extract_path'])

# ==========================================
# 2. API QUÉT TỰ ĐỘNG TỪ MÁY CHỦ CI/CD
# ==========================================
@router.post("/api/v1/cicd/scan")
async def cicd_automated_scan(
    file: UploadFile = File(...),
    project_id: int = Form(...),
    x_api_key: str = Header(None), 
    db: Session = Depends(get_db)
):
    expected_key = os.getenv("PIPELINE_SECRET_KEY")
    if not expected_key or x_api_key != expected_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Xác thực thất bại. API Key không hợp lệ.")

    upload_path = get_secure_temp_path(file.filename, prefix="cicd_")

    try:
        with open(upload_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        ingestion_data = ingestion_module.process_artifact(str(upload_path))
        analysis_data = analysis_module.analyze(ingestion_data)
        
        if not analysis_data or 'final_score' not in analysis_data:
            raise ValueError("Không tìm thấy thành phần mã nguồn hợp lệ để phân tích.")

        clean_analysis_data = sanitize_for_json(analysis_data)
        
        # [SỬA LỖI UX]: Ghi đè tên cho chuẩn CI/CD
        original_filename = file.filename
        clean_analysis_data['artifact'] = original_filename

        # [KIẾN TRÚC MỚI]: Bắt tín hiệu "Điểm mù dữ liệu" cho luồng CI/CD
        has_blind_spot = any(comp.get("is_blind_spot", False) for comp in clean_analysis_data.get("details", []))

        score = float(clean_analysis_data['final_score'])
        weakest = clean_analysis_data.get('weakest_link', {}).get('scores', {'CV': 0, 'CM': 0, 'CI': 0, 'CL': 0})
        
        # [PHÁN QUYẾT HUMAN-IN-THE-LOOP]
        if score >= 8.0:
            if has_blind_spot:
                status_decision = "PENDING_REVIEW" 
            else:
                status_decision = "APPROVED"
        elif score >= 5.0:
            status_decision = "PENDING"
        else:
            status_decision = "REJECTED"

        db_report = ScanReport(
            project_id=project_id,
            artifact_name=f"[CI/CD] {original_filename}", 
            hash_sha256=ingestion_data.get('hash', ''),
            score_cv=float(weakest.get('CV', 0)),
            score_cm=float(weakest.get('CM', 0)),
            score_ci=float(weakest.get('CI', 0)),
            score_cl=float(weakest.get('CL', 0)),
            final_score=score,
            decision=status_decision
        )
        db.add(db_report)
        db.commit()
        db.refresh(db_report)
        
        report_blob_path = settings.REPORT_DIR / f"full_audit_{db_report.id}.json"
        with open(report_blob_path, "w", encoding="utf-8") as f:
            json.dump(clean_analysis_data, f, ensure_ascii=False, indent=4)
        
        # CI/CD passed nếu điểm >= 5.0 (Cho phép cảnh báo nhưng không block pipeline cứng)
        is_passed = score >= 5.0 
        
        return {
            "status": "success",
            "ci_cd_passed": is_passed,
            "risk_score": score,
            "decision": status_decision,
            "details": "Bị chặn bởi Security Gate." if not is_passed else "Vượt qua Security Gate.",
            "weakest_component": clean_analysis_data.get('weakest_link')
        }
        
    except Exception as e:
        db.rollback()
        logger.error(f"CRITICAL ERROR in /cicd/scan:\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="Lỗi CI/CD Worker nội bộ.")
        
    finally:
        if upload_path.exists():
            upload_path.unlink()
        if 'ingestion_data' in locals() and 'extract_path' in ingestion_data:
            ingestion_module.cleanup_artifact(ingestion_data['extract_path'])

# ==========================================
# 3. API XUẤT BÁO CÁO ĐA ĐỊNH DẠNG
# ==========================================
@router.get("/api/v1/export/{report_id}")
async def export_audit_report(
    report_id: int, 
    format: str = Query("pdf", description="Định dạng xuất: pdf, word, excel"), 
    db: Session = Depends(get_db)
):
    report = db.query(ScanReport).filter(ScanReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Không tìm thấy báo cáo.")

    report_blob_path = settings.REPORT_DIR / f"full_audit_{report.id}.json"
    
    if report_blob_path.exists():
        with open(report_blob_path, "r", encoding="utf-8") as f:
            analysis_data = json.load(f)
    else:
        raise HTTPException(status_code=404, detail="Dữ liệu chi tiết của phiên quét này đã bị xóa hoặc mất mát.")

    try:
        file_path = exporter_module.export_report(analysis_data, format_type=format.lower())
        return FileResponse(
            path=file_path, 
            filename=file_path.name,
            media_type="application/octet-stream"
        )
    except Exception as e:
        logger.error("LỖI EXPORT FILE:")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Lỗi tạo file: {str(e)}")