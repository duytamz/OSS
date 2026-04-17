import hashlib
import subprocess
import os
import requests
import logging
import yara
from pathlib import Path
from urllib.parse import quote_plus
from security_gate.core.config import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ScannerIntegrator")

class ScannerIntegrator:
    """
    Tích hợp các công cụ quét bảo mật cho chuỗi cung ứng phần mềm.
    Tập trung vào tính toàn vẹn và đánh giá rủi ro theo ASVS 5.0.0.
    """
    
    # Caching rule YARA ở mức Class để không phải đọc/biên dịch lại file nhiều lần
    _yara_rules = None

    @classmethod
    def _get_yara_rules(cls):
        """Lazy-loading & Caching YARA rules để tối ưu hiệu năng."""
        if cls._yara_rules is None:
            try:
                # Đảm bảo đường dẫn file được tính toán tương đối an toàn
                base_dir = Path(__file__).resolve().parent.parent
                rules_path = base_dir / "core" / "rules" / "malicious_patterns.yar"
                cls._yara_rules = yara.compile(filepath=str(rules_path))
                logger.info("Đã biên dịch thành công YARA rules vào bộ nhớ.")
            except Exception as e:
                logger.error(f"Lỗi khởi tạo YARA Rules: {e}")
        return cls._yara_rules

    @staticmethod
    def generate_hash(file_path: str) -> str:
        """Tạo dấu vân tay số (Digital Fingerprint) sử dụng SHA-256."""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except FileNotFoundError:
            logger.error(f"Không tìm thấy file để tạo hash: {file_path}")
            return ""

    @staticmethod
    def run_syft(source_dir: str, output_file: str):
        """Trích xuất SBOM CycloneDX (Whitebox Analysis)."""
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        cmd = ["syft", f"dir:{source_dir}", "-o", "cyclonedx-json", "--quiet"]

        try:
            with open(output_file, "w", encoding="utf-8") as f:
                subprocess.run(
                    cmd, stdout=f, stderr=subprocess.PIPE, check=True, text=True
                )
            logger.info(f"SBOM đã được tạo thành công tại: {output_file}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Syft thất bại: {e.stderr}")
            raise RuntimeError(f"Lỗi khi chạy Syft: {e.stderr}")

    @staticmethod
    def map_cvss_to_asvs(cvss: float) -> float:
        """Ánh xạ CVSS sang thang điểm 1-10 theo Hàm bậc thang NIST."""
        if cvss >= 9.0: return 0.0  # Critical
        if cvss >= 7.0: return 2.0  # High
        if cvss >= 4.0: return 5.0  # Medium
        if cvss > 0.0:  return 8.0  # Low
        return 10.0                 # Safe

    @staticmethod
    def fetch_scorecard(pkg_name: str, ecosystem: str) -> float:
        """Truy vấn sức khỏe dự án từ deps.dev API với khả năng tự sửa lỗi hệ sinh thái."""
        if not pkg_name: 
            return 5.0
            
        eco_map = {"pypi": "pypi", "npm": "npm", "go": "go", "maven": "maven"}
        java_keywords = ['apache', 'tomcat', 'catalina', 'commons', 'servlet', 'glassfish']
        
        target_eco = "maven" if any(key in pkg_name.lower() for key in java_keywords) else eco_map.get(ecosystem.lower(), "pypi")

        try:
            encoded_name = quote_plus(pkg_name)
            url = f"https://api.deps.dev/v3alpha/systems/{target_eco}/packages/{encoded_name}"
            
            res = requests.get(url, timeout=5)
            if res.status_code == 404:
                return 5.0 
                
            res.raise_for_status()
            data = res.json()
            return float(data.get('scorecard', {}).get('overallScore', 5.0))
        except Exception as e:
            logger.debug(f"Fetch Scorecard failed for {pkg_name}: {e}")
            return 5.0

    @staticmethod
    def check_slsa(temp_dir: str) -> float:
        """Xác minh tính toàn vẹn (Integrity) theo V14 của ASVS."""
        for root, _, files in os.walk(temp_dir):
            for file in files:
                if file in ["attestation.json", "intoto.json"]:
                    return 10.0 
        return 6.0 

    @classmethod
    def scan_yara(cls, source_dir: Path) -> int:
        """Thực thi YARA Engine quét mã độc theo ASVS V10."""
        rules = cls._get_yara_rules()
        if not rules:
            return 0 # Fail-safe nếu không load được rules
            
        match_count = 0
        
        try:
            for root, _, files in os.walk(source_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    # Bỏ qua các file không phải text/code để tối ưu tốc độ
                    if not file_path.endswith(('.py', '.js', '.sh', '.json')):
                        continue
                        
                    try:
                        matches = rules.match(file_path)
                        if matches:
                            match_count += len(matches)
                    except Exception:
                        pass # Bỏ qua an toàn nếu file bị lỗi permission/encoding
            return match_count
        except Exception as e:
            logger.error(f"Lỗi hệ thống khi quét YARA: {e}")
            return 0 

    @staticmethod
    def check_virustotal(file_hash: str) -> int:
        """Truy vấn VirusTotal để lấy số lượng engine báo cáo mã độc (Malicious)."""
        if not settings.VT_API_KEY: 
            return 0
            
        try:
            headers = {"x-apikey": settings.VT_API_KEY}
            res = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers, timeout=5)
            
            # An toàn: Kiểm tra status code trước khi parse JSON để tránh JSONDecodeError
            res.raise_for_status() 
            data = res.json()
            
            return data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
        except Exception as e:
            logger.debug(f"Lỗi truy vấn VirusTotal cho hash {file_hash}: {e}")
            return 0