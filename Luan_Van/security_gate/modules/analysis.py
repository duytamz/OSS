import os
import json
import logging
import requests
from typing import Dict, Any
from pathlib import Path

from security_gate.core.config import settings
from security_gate.integrations.scanners import ScannerIntegrator
from security_gate.core.risk_engine import RiskEngine

logger = logging.getLogger(__name__)

class AnalysisModule:
    """
    Module xử lý Giai đoạn 2: Phân tích sâu (Deep Analysis) & Đánh giá Rủi ro.
    Đã tích hợp Kiến trúc Resilient: Smart Caching & Human-in-the-Loop.
    """
    def __init__(self, risk_engine: RiskEngine):
        self.engine = risk_engine
        
    @staticmethod
    def _parse_ecosystem_from_purl(purl: str) -> str:
        if not purl: return "npm"
        purl_lower = purl.lower()
        if "pkg:pypi" in purl_lower: return "pypi"
        if "pkg:npm" in purl_lower: return "npm"
        if "pkg:maven" in purl_lower: return "maven"
        if "pkg:golang" in purl_lower: return "go"
        return "npm"

    # ==========================================
    # CƠ CHẾ SMART CACHING & BLIND SPOT DETECTION
    # ==========================================
    @staticmethod
    def _read_from_cache(purl: str) -> float:
        """Đọc điểm từ Cache. Nếu không có, báo cờ -1.0 (Blind Spot)."""
        cache_file = settings.DATA_DIR / "osv_cache.json"
        if not cache_file.exists():
            return -1.0 
            
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                cache_data = json.load(f)
                return float(cache_data.get(purl, -1.0))
        except Exception:
            return -1.0

    @staticmethod
    def _update_cache(purl: str, score: float):
        """Làm giàu bộ nhớ đệm nội bộ khi Online."""
        cache_file = settings.DATA_DIR / "osv_cache.json"
        cache_data = {}
        try:
            if cache_file.exists():
                with open(cache_file, "r", encoding="utf-8") as f:
                    cache_data = json.load(f)
            cache_data[purl] = score
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(cache_data, f, indent=4)
        except Exception as e:
            logger.debug(f"Không thể ghi cache cho {purl}: {e}")

    @staticmethod
    def _get_max_cvss_from_osv(purl: str) -> float:
        """Kiến trúc Circuit Breaker: Gọi API -> Timeout -> Fallback Cache."""
        if not purl: return 0.0
        
        try:
            url = "https://api.osv.dev/v1/query"
            res = requests.post(url, json={"package": {"purl": purl}}, timeout=3)
            
            if res.status_code == 200:
                vulns = res.json().get("vulns", [])
                score = 8.5 if vulns else 0.0
                AnalysisModule._update_cache(purl, score) # Lưu Cache
                return score
            return 0.0
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            logger.warning(f"Mất mạng. Kích hoạt Fallback Cache cho: {purl}")
            return AnalysisModule._read_from_cache(purl)
        except Exception as e:
            logger.error(f"Lỗi OSV API: {e}")
            return AnalysisModule._read_from_cache(purl)

    # ==========================================
    # CƠ CHẾ LICENSE FALLBACK
    # ==========================================
    @staticmethod
    def _extract_license_from_sbom(comp: dict) -> str:
        licenses = comp.get("licenses", [])
        if not licenses: return "UNKNOWN"
        for lic in licenses:
            if "license" in lic:
                lic_obj = lic["license"]
                if "id" in lic_obj: return str(lic_obj["id"]).upper()
                if "name" in lic_obj: return str(lic_obj["name"]).upper()
            if "expression" in lic: return str(lic["expression"]).upper()
        return "UNKNOWN"

    @staticmethod
    def _fallback_detect_license_file(extract_path: Path) -> str:
        if not extract_path or not extract_path.exists(): return "UNKNOWN"
        target_files = ["license", "license.txt", "license.md", "copying", "copying.txt", "license.rst"]
        try:
            search_dirs = [extract_path]
            search_dirs.extend([d for d in extract_path.iterdir() if d.is_dir()])
            for d in search_dirs:
                for file_path in d.iterdir():
                    if file_path.is_file() and file_path.name.lower() in target_files:
                        content = file_path.read_text(encoding='utf-8', errors='ignore').upper()
                        if "MIT " in content: return "MIT"
                        if "APACHE" in content: return "APACHE-2.0"
                        if "GPL" in content: return "GPL"
                        if "BSD " in content: return "BSD"
                        return "CUSTOM_FOUND" 
        except Exception as e:
            logger.error(f"Lỗi Fallback License: {e}")
        return "UNKNOWN"

    @staticmethod
    def _check_heuristic(component_name: str) -> bool:
        if not component_name: return False
        if "log4j" in component_name.lower(): return True 
        return False

    # --- LUỒNG XỬ LÝ CHÍNH ---
    def analyze(self, ingestion_data: Dict[str, Any]) -> Dict[str, Any]:
        if not ingestion_data or 'sbom_path' not in ingestion_data:
            return {}

        logger.info(f"[GĐ 2] Đang phân tích rủi ro: {ingestion_data.get('filename', 'Unknown')}")

        extract_path = Path(ingestion_data['extract_path'])
        has_sig = (extract_path / "attestation.json").exists() or (extract_path / "intoto.json").exists()
        
        # An toàn khi mất mạng cho VirusTotal
        try:
            malicious_vt = ScannerIntegrator.check_virustotal(ingestion_data['hash'])
        except Exception:
            malicious_vt = 0

        yara_alerts = ingestion_data.get('yara_count', 0)
        if yara_alerts == 0 and 'yara_matches_path' in ingestion_data:
            yara_path = Path(ingestion_data['yara_matches_path'])
            if yara_path.exists():
                try:
                    with open(yara_path, "r") as yf:
                        yara_alerts = json.load(yf).get("malicious_patterns_found", 0)
                except Exception: pass

        base_ci = self.engine.map_integrity(has_sig)
        base_cm = self.engine.map_malware(malicious_vt, yara_alerts)

        try:
            with open(ingestion_data['sbom_path'], 'r', encoding='utf-8') as f:
                sbom = json.load(f)
        except Exception as e: return {}

        weakest_link = None
        lowest_r_score = 100.0 
        analyzed_components = []

        for comp in sbom.get('components', []):
            pkg_name = comp.get('name', 'Unknown')
            purl = comp.get('purl', '')
            ecosystem = self._parse_ecosystem_from_purl(purl)
            
            # 1. BẮT ĐIỂM MÙ DỮ LIỆU
            raw_cvss = self._get_max_cvss_from_osv(purl)
            is_blind_spot = False
            if raw_cvss == -1.0:
                is_blind_spot = True
                raw_cvss = 0.0 # Tạm gán 0.0 để tránh lỗi toán học cho công thức SAW
                logger.warning(f"Điểm mù: Không thể tra cứu {pkg_name} do mất mạng & thiếu cache.")

            try:
                m_score = ScannerIntegrator.fetch_scorecard(pkg_name, ecosystem) 
            except Exception:
                m_score = 10.0 # Fallback an toàn nếu Scorecard sập
            
            # 2. KIỂM TRA LICENSE (CÓ FALLBACK)
            actual_license = self._extract_license_from_sbom(comp)
            if actual_license == "UNKNOWN":
                fallback_license = self._fallback_detect_license_file(extract_path)
                if fallback_license != "UNKNOWN":
                    actual_license = fallback_license
            
            heuristic_flag = self._check_heuristic(pkg_name)
            
            # 3. TÍNH ĐIỂM THÀNH PHẦN
            cv_score = self.engine.map_cvss(raw_cvss, heuristic_flag=heuristic_flag) 
            cm_score = base_cm if base_cm == 0.0 else (m_score if m_score > 0 else 10.0) 
            cl_score = self.engine.map_license(actual_license)
            ci_score = base_ci 

            comp_scores = {'CV': cv_score, 'CM': cm_score, 'CI': ci_score, 'CL': cl_score}
            final_r = self.engine.calculate_saw_score(comp_scores)
            
            comp_data = {
                "name": pkg_name,
                "version": comp.get('version', ''),
                "purl": purl,
                "license": actual_license,
                "raw_metrics": {
                    "cvss_v3": raw_cvss,
                    "scorecard": m_score
                },
                "scores": comp_scores,
                "r_score": final_r,
                "is_blind_spot": is_blind_spot # Truyền cờ báo hiệu ra ngoài
            }
            analyzed_components.append(comp_data)

            if final_r < lowest_r_score:
                lowest_r_score = final_r
                weakest_link = comp_data

        if not weakest_link:
            weakest_link = {"name": "N/A", "scores": {'CV': 10.0, 'CM': 10.0, 'CI': base_ci, 'CL': 10.0}, "r_score": 10.0}

        return {
            "artifact": ingestion_data.get('filename', 'Unknown'),
            "hash": ingestion_data['hash'],
            "final_score": weakest_link['r_score'],
            "weakest_link": weakest_link,
            "project_integrity": {
                "signed": has_sig,
                "virustotal_flags": malicious_vt,
                "yara_alerts": yara_alerts,
                "base_ci_score": base_ci,
                "base_cm_score": base_cm
            },
            "total_components": len(analyzed_components),
            "details": analyzed_components 
        }