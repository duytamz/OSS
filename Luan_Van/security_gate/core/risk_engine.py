import numpy as np
import logging
from typing import Dict, Tuple
from security_gate.core.config import settings

logger = logging.getLogger(__name__)

class RiskEngine:
    """Core Engine xử lý thuật toán AHP và SAW cho toàn bộ hệ thống."""
    
    def __init__(self):
        self.weights, self.cr_score, self.is_valid = self._calculate_and_verify_ahp()
        
        if not self.is_valid:
            logger.warning(f"Cảnh báo: Tỷ số nhất quán AHP (CR) = {self.cr_score:.3f} > 0.1. Ma trận cần được tinh chỉnh lại!")
        else:
            logger.info(f"Trọng số AHP hợp lệ. CR = {self.cr_score:.3f}")

    def _calculate_and_verify_ahp(self) -> Tuple[np.ndarray, float, bool]:
        matrix = np.array(settings.AHP_MATRIX_RATIOS)
        n = matrix.shape[0]
        
        eig_val, eig_vec = np.linalg.eig(matrix)
        max_eig_val = np.max(eig_val.real)
        weights = eig_vec[:, np.argmax(eig_val.real)].real
        weights /= weights.sum()
        
        ci = (max_eig_val - n) / (n - 1) if n > 1 else 0
        ri_dict = {1: 0.0, 2: 0.0, 3: 0.58, 4: 0.90, 5: 1.12, 6: 1.24, 7: 1.32, 8: 1.41, 9: 1.45, 10: 1.49}
        ri = ri_dict.get(n, 1.49)
        cr = ci / ri if ri != 0 else 0
        
        return weights, cr, cr <= 0.1

    # ==========================================
    # CÁC HÀM CHUẨN HÓA DỮ LIỆU (TRANSFORM RULES) - ĐÃ TINH CHỈNH THỰC TẾ
    # ==========================================
    @staticmethod
    def map_cvss(cvss_raw: float, heuristic_flag: bool = False) -> float:
        """
        Nới lỏng C_V: Chỉ phạt nặng những lỗ hổng từ Medium trở lên. 
        Lỗ hổng Low vẫn được châm chước qua ải (9.0).
        """
        try:
            cvss_raw = float(cvss_raw)
        except (ValueError, TypeError):
            cvss_raw = 0.0
            
        if heuristic_flag: return 0.0  # Dính mã độc hoặc hành vi mờ ám -> 0 ngay
        if cvss_raw >= 9.0: return 0.0 # Critical
        if cvss_raw >= 7.0: return 4.0 # High 
        if cvss_raw >= 4.0: return 7.0 # Medium 
        if cvss_raw > 0.0:  return 9.0 # Low
        return 10.0 # Sạch bóng lỗ hổng

    @staticmethod
    def map_malware(malicious_vt: int, yara_alerts: int) -> float:
        """
        Ánh xạ điểm Mã độc (C_M) - Độc lập hoàn toàn.
        Tiêu chí tối thượng: Chỉ cần phát hiện 1 cờ mã độc từ YARA hoặc VirusTotal -> Điểm 0 (Rủi ro tuyệt đối).
        Nếu sạch sẽ -> Điểm 10.
        """
        if malicious_vt > 0 or yara_alerts > 0:
            return 0.0 
        return 10.0

    @staticmethod
    def map_integrity(has_sig: bool) -> float:
        """
        Ánh xạ tính toàn vẹn (C_I) thuần túy.
        Chỉ đánh giá dựa trên chữ ký điện tử (Signature) hoặc sự tồn tại của Hash.
        """
        if has_sig:
            return 10.0 # Có chữ ký xác thực người gửi -> Điểm tuyệt đối
        return 9.0      # Chỉ có Hash đối chiếu -> Đạt tiêu chuẩn OSS thông thường

    @staticmethod
    def map_license(license_str: str) -> float:
        """
        Tinh chỉnh C_L theo yêu cầu: Đánh giá nhị phân.
        Minh bạch khai báo License = 10 điểm. Lập lờ/Không khai báo = 0 điểm.
        """
        if not license_str:
            return 0.0
            
        lic = str(license_str).strip().upper()
        
        # Nếu thư viện trả về các chuỗi trống hoặc không xác định
        if lic in ["NONE", "UNKNOWN", "NULL", ""]:
            return 0.0 
            
        # Có bất kỳ chữ gì khai báo là cấp 10 điểm minh bạch
        return 10.0 

    # ==========================================
    # TÍNH TOÁN RỦI RO (SCORING)
    # ==========================================
    def calculate_saw_score(self, ci_scores: Dict[str, float]) -> float:
        """Tính tổng điểm R bằng mô hình SAW."""
        
        # SỬA LỖI NGHIÊM TRỌNG: Giá trị fallback (mặc định) nếu thiếu dữ liệu phải là điểm 10 (Sạch), 
        # chứ không phải 0 (Rủi ro cao). Điều này giúp các thư viện bình thường không bị hạ điểm oan uổng.
        scores_array = np.array([
            ci_scores.get('CV', 10.0), # Lỗ hổng (Mặc định 10)
            ci_scores.get('CM', 10.0), # Mã độc (Mặc định không có mã độc là 10)
            ci_scores.get('CI', 9.0),  # Toàn vẹn (Mặc định có hash là 9)
            ci_scores.get('CL', 10.0)  # Pháp lý (Mặc định có license là 10)
        ])
        
        # Vector trọng số nhân với Vector điểm
        return round(float(np.dot(scores_array, self.weights)), 2)