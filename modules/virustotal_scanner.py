import os
import time
import requests
import streamlit as st
from typing import Dict, Any, Optional, Callable, Tuple

VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"
MAX_UPLOAD_SIZE_MB = 32


def get_api_key() -> str:
    """
    Retrieve VirusTotal API key securely from environment, Streamlit secrets,
    or session override. Never logs or exposes the key.
    """
    # 1. Environment variable
    env_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if env_key and env_key.strip():
        return env_key.strip()

    # 2. Streamlit secrets
    try:
        if "VIRUSTOTAL_API_KEY" in st.secrets and st.secrets["VIRUSTOTAL_API_KEY"]:
            return str(st.secrets["VIRUSTOTAL_API_KEY"]).strip()
        if "VIRUSTOTAL" in st.secrets and "API_KEY" in st.secrets["VIRUSTOTAL"]:
            return str(st.secrets["VIRUSTOTAL"]["API_KEY"]).strip()
        if "virustotal_api_key" in st.secrets and st.secrets["virustotal_api_key"]:
            return str(st.secrets["virustotal_api_key"]).strip()
    except Exception:
        pass

    # 3. Session state override
    session_key = st.session_state.get("vt_api_key_override", "")
    if session_key and session_key.strip():
        return session_key.strip()

    return ""


def check_existing_report(file_hash: str, api_key: str) -> Dict[str, Any]:
    """
    Query VirusTotal API using SHA-256 hash to check if an analysis already exists.
    Saves API quota and bandwidth by avoiding redundant file uploads.
    """
    if not api_key:
        return {"success": False, "error": "VirusTotal API key is missing."}

    url = f"{VIRUSTOTAL_BASE_URL}/files/{file_hash}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {"success": True, "found": True, "data": data}
        elif response.status_code == 404:
            return {"success": True, "found": False}
        elif response.status_code in (401, 403):
            return {
                "success": False,
                "error": "Invalid or unauthorized VirusTotal API key. Please check your key configuration.",
            }
        elif response.status_code == 429:
            return {
                "success": False,
                "error": "VirusTotal API rate limit exceeded. Please wait a moment before submitting again.",
            }
        else:
            return {
                "success": False,
                "error": f"VirusTotal service error (HTTP {response.status_code}).",
            }
    except requests.exceptions.Timeout:
        return {"success": False, "error": "Network timeout connecting to VirusTotal API."}
    except requests.exceptions.RequestException as e:
        return {"success": False, "error": f"Network error during VirusTotal API check: {str(e)}"}


def upload_file(file_name: str, file_bytes: bytes, api_key: str) -> Dict[str, Any]:
    """
    Upload file bytes to VirusTotal API for multi-engine analysis.
    Safely handles payloads up to MAX_UPLOAD_SIZE_MB.
    """
    if not api_key:
        return {"success": False, "error": "VirusTotal API key is missing."}

    file_size_mb = len(file_bytes) / (1024 * 1024)
    if file_size_mb > MAX_UPLOAD_SIZE_MB:
        return {
            "success": False,
            "error": f"File size ({file_size_mb:.2f} MB) exceeds maximum allowed limit ({MAX_UPLOAD_SIZE_MB} MB) for VirusTotal submission.",
        }

    url = f"{VIRUSTOTAL_BASE_URL}/files"
    headers = {"x-apikey": api_key}
    files = {"file": (file_name, file_bytes)}

    try:
        response = requests.post(url, headers=headers, files=files, timeout=60)
        if response.status_code == 200:
            analysis_id = response.json().get("data", {}).get("id")
            if analysis_id:
                return {"success": True, "analysis_id": analysis_id}
            return {"success": False, "error": "Invalid response payload from VirusTotal API."}
        elif response.status_code in (401, 403):
            return {
                "success": False,
                "error": "Invalid or unauthorized VirusTotal API key. Please check your API key.",
            }
        elif response.status_code == 429:
            return {
                "success": False,
                "error": "VirusTotal API rate limit exceeded. Please wait a moment before trying again.",
            }
        else:
            return {
                "success": False,
                "error": f"VirusTotal upload error (HTTP {response.status_code}).",
            }
    except requests.exceptions.Timeout:
        return {"success": False, "error": "Upload connection timed out while sending file to VirusTotal."}
    except requests.exceptions.RequestException as e:
        return {"success": False, "error": f"Network error during VirusTotal upload: {str(e)}"}


def poll_analysis_status(
    analysis_id: str,
    api_key: str,
    progress_callback: Optional[Callable[[str], None]] = None,
    max_timeout: int = 120,
    poll_interval: int = 5,
) -> Dict[str, Any]:
    """
    Check the status of an in-flight analysis periodically until completion or timeout.
    """
    if not api_key:
        return {"success": False, "error": "VirusTotal API key is missing."}

    url = f"{VIRUSTOTAL_BASE_URL}/analyses/{analysis_id}"
    headers = {"x-apikey": api_key}

    start_time = time.time()
    while time.time() - start_time < max_timeout:
        try:
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                data = response.json().get("data", {})
                attributes = data.get("attributes", {})
                status = attributes.get("status", "queued")

                if status == "completed":
                    if progress_callback:
                        progress_callback("Analysis complete! Fetching security engine report...")
                    return {"success": True, "data": data}
                else:
                    if progress_callback:
                        progress_callback(
                            f"Waiting for security engines... Status: {status.replace('_', ' ').capitalize()} (Elapsed: {int(time.time() - start_time)}s)"
                        )
                    time.sleep(poll_interval)
            elif response.status_code in (401, 403):
                return {"success": False, "error": "Invalid or unauthorized VirusTotal API key."}
            elif response.status_code == 429:
                return {"success": False, "error": "VirusTotal API rate limit exceeded during polling."}
            else:
                return {"success": False, "error": f"Polling error from VirusTotal (HTTP {response.status_code})."}
        except requests.exceptions.RequestException as e:
            return {"success": False, "error": f"Network error while polling VirusTotal: {str(e)}"}

    return {
        "success": False,
        "error": f"VirusTotal analysis polling timed out after {max_timeout} seconds. Analysis is still in progress on VirusTotal.",
    }


def parse_vt_data(vt_data: Dict[str, Any], fallback_filename: str = "", fallback_sha256: str = "") -> Dict[str, Any]:
    """
    Convert raw VirusTotal API object (file or analysis type) into a clean, structured dictionary.
    """
    data_type = vt_data.get("type", "")
    attributes = vt_data.get("attributes", {})

    if data_type == "file":
        stats = attributes.get("last_analysis_stats", {})
        results = attributes.get("last_analysis_results", {})
        sha256 = vt_data.get("id") or attributes.get("sha256") or fallback_sha256
        file_size = attributes.get("size", 0)
        filename = attributes.get("meaningful_name") or fallback_filename or "Uploaded File"
    else:  # analysis type
        stats = attributes.get("stats", {})
        results = attributes.get("results", {})
        sha256 = attributes.get("sha256") or vt_data.get("meta", {}).get("file_info", {}).get("sha256") or fallback_sha256
        file_size = attributes.get("size", 0)
        filename = fallback_filename or "Uploaded File"

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    harmless = stats.get("harmless", 0)
    timeout = stats.get("timeout", 0) + stats.get("confirmed-timeout", 0)
    unsupported = stats.get("type-unsupported", 0)
    failure = stats.get("failure", 0)

    total_engines = sum([malicious, suspicious, undetected, harmless, timeout, unsupported, failure])
    if total_engines == 0 and results:
        total_engines = len(results)

    # Format engine details list
    engine_list = []
    for engine_name, engine_info in results.items():
        category = engine_info.get("category", "undetected")
        result = engine_info.get("result") or "—"
        engine_list.append(
            {
                "engine": engine_name,
                "category": category.capitalize(),
                "result": result,
                "is_flagged": category in ("malicious", "suspicious"),
            }
        )

    # Sort flagged engines (malicious / suspicious) to top
    engine_list.sort(key=lambda x: (not x["is_flagged"], x["engine"].lower()))

    report_url = f"https://www.virustotal.com/gui/file/{sha256}" if sha256 else ""

    return {
        "filename": filename,
        "sha256": sha256,
        "file_size": file_size,
        "total_engines": total_engines,
        "malicious": malicious,
        "suspicious": suspicious,
        "undetected": undetected,
        "harmless": harmless,
        "timeout": timeout,
        "unsupported": unsupported,
        "failure": failure,
        "engines": engine_list,
        "report_url": report_url,
    }


def get_risk_interpretation(malicious_count: int, suspicious_count: int, total_engines: int) -> Tuple[str, str, str, str]:
    """
    Provide clear interpretation of scan results adhering strictly to security guidelines.
    Returns (severity_level, css_badge_class, title, message).
    """
    total_flagged = malicious_count + suspicious_count

    if malicious_count >= 3 or total_flagged >= 5:
        return (
            "HIGH_RISK",
            "badge-very-weak",
            "⚠️ High Risk Detected",
            "Multiple security engines detected this file as potentially malicious. Treat the file as unsafe and do not open or execute it.",
        )
    elif total_flagged > 0:
        return (
            "LOW_RISK",
            "badge-weak",
            "⚡ Low/Moderate Risk Flagged",
            "Some security engines detected or flagged this file. Review the individual engine results and file context carefully.",
        )
    else:
        return (
            "CLEAN",
            "badge-very-strong",
            "✅ No Detections Found",
            "VirusTotal currently reports no detections among the engines that analyzed this file. Note: This does NOT guarantee that the file is malware-free.",
        )
