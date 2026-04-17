import os
import json
import shutil
import logging
import uuid
import zipfile
import tarfile
from pathlib import Path
from typing import Dict, Any

try:
    import rarfile
except ImportError:
    rarfile = None

from security_gate.core.config import settings
from security_gate.integrations.scanners import ScannerIntegrator

logger = logging.getLogger(__name__)

class SecurityError(Exception):
    pass

class IngestionModule:
    def __init__(self):
        self.extracted_dir = settings.EXTRACTED_DIR
        self.sbom_dir = settings.SBOM_DIR
        self.data_dir = settings.DATA_DIR
        
        for d in [self.extracted_dir, self.sbom_dir, self.data_dir]:
            d.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _is_safe_path(basedir: Path, path: str) -> bool:
        basedir_path = basedir.resolve()
        target_path = (basedir / path).resolve()
        return target_path.is_relative_to(basedir_path)

    def _secure_extract(self, archive_path: Path, extract_to: Path):
        filename = archive_path.name.lower()
        extract_to.mkdir(parents=True, exist_ok=True)

        try:
            # 1. ZIP, JAR, WHL
            if filename.endswith(('.zip', '.jar', '.whl')):
                with zipfile.ZipFile(str(archive_path), 'r') as zip_ref:
                    for member in zip_ref.namelist():
                        if not self._is_safe_path(extract_to, member):
                            raise SecurityError(f"Phát hiện tấn công Zip Slip ở file: {member}")
                    zip_ref.extractall(extract_to)
                    logger.info(f"Đã giải nén ZIP an toàn: {filename}")

            # 2. TARBALL (.tar.gz, .tgz, .tar, .gz)
            elif filename.endswith(('.tar.gz', '.tgz', '.tar', '.gz')):
                with tarfile.open(str(archive_path), 'r:*') as tar_ref:
                    for member in tar_ref.getmembers():
                        if not self._is_safe_path(extract_to, member.name):
                            raise SecurityError(f"Phát hiện tấn công Tar Slip ở file: {member.name}")
                    tar_ref.extractall(extract_to)
                    logger.info(f"Đã giải nén TARBALL an toàn: {filename}")

            # 3. RAR
            elif filename.endswith('.rar'):
                if rarfile is None:
                    raise ImportError("Thư viện 'rarfile' chưa được cài đặt. Chạy: pip install rarfile")
                with rarfile.RarFile(str(archive_path), 'r') as rar_ref:
                    for member in rar_ref.namelist():
                        if not self._is_safe_path(extract_to, member):
                            raise SecurityError(f"Phát hiện tấn công Rar Slip ở file: {member}")
                    rar_ref.extractall(extract_to)
                    logger.info(f"Đã giải nén RAR an toàn: {filename}")

            else:
                raise ValueError(f"Định dạng không hỗ trợ: {filename}")

        except Exception as e:
            logger.error(f"Lỗi giải nén {filename}: {str(e)}")
            raise

    def process_artifact(self, file_path: str) -> Dict[str, Any]:
        path = Path(file_path)
        if not path.exists():
            return {}

        try:
            f_hash = ScannerIntegrator.generate_hash(str(path))
            if not f_hash: raise ValueError("Không thể tạo mã băm SHA256.")
            
            session_id = f"{f_hash[:10]}_{uuid.uuid4().hex[:8]}"
            extract_path = self.extracted_dir / session_id
            
            try:
                self._secure_extract(path, extract_path)
            except Exception as e:
                logger.error(f"Lỗi giải nén hoặc phát hiện mã độc: {e}")
                # Nếu không giải nén được, chép thẳng file vào (trường hợp code đơn lẻ)
                shutil.copy2(str(path), extract_path)

            sbom_path = self.sbom_dir / f"sbom_{session_id}.json"
            ScannerIntegrator.run_syft(str(extract_path), str(sbom_path))
            
            yara_match_count = ScannerIntegrator.scan_yara(extract_path)
            yara_path = self.data_dir / f"yara_{session_id}.json"
            with open(yara_path, "w", encoding="utf-8") as yf:
                json.dump({"malicious_patterns_found": yara_match_count}, yf, indent=4)
            
            meta_data = {
                "filename": path.name, "hash": f_hash, "extract_path": str(extract_path),
                "sbom_path": str(sbom_path), "yara_matches_path": str(yara_path), "yara_count": yara_match_count
            }
            return meta_data

        except Exception as e:
            logger.error(f"Lỗi nghiêm trọng ở GĐ1 (Ingestion): {str(e)}")
            return {}
            
    def cleanup_artifact(self, extract_path: str):
        try:
            path = Path(extract_path)
            if path.exists() and path.is_dir():
                shutil.rmtree(path)
        except Exception as e:
            logger.warning(f"Không thể dọn dẹp thư mục {extract_path}: {e}")