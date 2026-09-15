import re
import ipaddress
import urllib.parse
import streamlit as st
from utils.theme import page_header
from utils.security import record_activity
from modules.risk_engine import add_finding
from modules.security_events import log_event
from modules.virustotal_scanner import get_api_key, check_existing_report


def classify_ioc(value: str) -> dict:
    """Analyze input string and automatically detect IOC type, attributes, and basic risk classification."""
    val = value.strip()
    if not val:
        return {"valid": False, "error": "Empty IOC input provided."}

    # 1. IP Address Check
    try:
        ip_obj = ipaddress.ip_address(val)
        return {
            "valid": True,
            "type": f"IPv{ip_obj.version} Address",
            "ioc_category": "IP",
            "value": str(ip_obj),
            "attributes": {
                "Is Public": not ip_obj.is_private,
                "Is Private / RFC1918": ip_obj.is_private,
                "Is Loopback": ip_obj.is_loopback,
                "Is Reserved": ip_obj.is_reserved,
                "Is Multicast": ip_obj.is_multicast,
                "Is Global": ip_obj.is_global,
            },
            "risk_assessment": "PUBLIC_IP" if ip_obj.is_global else "PRIVATE_LOCAL_IP",
        }
    except ValueError:
        pass

    # 2. Cryptographic Hash Check (MD5, SHA-1, SHA-256)
    if re.fullmatch(r"[a-fA-F0-9]{64}", val):
        return {
            "valid": True,
            "type": "SHA-256 Hash Digest",
            "ioc_category": "HASH",
            "value": val.lower(),
            "attributes": {
                "Algorithm": "SHA-256",
                "Hash Bit-length": "256 bits (64 hex characters)",
                "Cryptographic Integrity Standard": "Strong (NIST Approved)",
            },
            "risk_assessment": "HASH_LOOKUP_SUPPORTED",
        }
    elif re.fullmatch(r"[a-fA-F0-9]{40}", val):
        return {
            "valid": True,
            "type": "SHA-1 Hash Digest",
            "ioc_category": "HASH",
            "value": val.lower(),
            "attributes": {
                "Algorithm": "SHA-1",
                "Hash Bit-length": "160 bits (40 hex characters)",
                "Cryptographic Integrity Standard": "Legacy / Deprecated for Digital Signatures",
            },
            "risk_assessment": "HASH_LOOKUP_SUPPORTED",
        }
    elif re.fullmatch(r"[a-fA-F0-9]{32}", val):
        return {
            "valid": True,
            "type": "MD5 Hash Digest",
            "ioc_category": "HASH",
            "value": val.lower(),
            "attributes": {
                "Algorithm": "MD5",
                "Hash Bit-length": "128 bits (32 hex characters)",
                "Cryptographic Integrity Standard": "Vulnerable to Collisions",
            },
            "risk_assessment": "HASH_LOOKUP_SUPPORTED",
        }

    # 3. Email Address Check
    email_match = re.fullmatch(r"[^@\s]+@([^@\s]+\.[^@\s]+)", val)
    if email_match:
        domain = email_match.group(1)
        return {
            "valid": True,
            "type": "Email Address",
            "ioc_category": "EMAIL",
            "value": val,
            "attributes": {
                "Local Part": val.split("@")[0],
                "Domain Part": domain,
                "Domain Subdomains": domain.count("."),
            },
            "risk_assessment": "POTENTIAL_PHISHING_SENDER",
        }

    # 4. URL Check
    if val.startswith(("http://", "https://", "ftp://")):
        parsed = urllib.parse.urlparse(val)
        return {
            "valid": True,
            "type": f"Web URL ({parsed.scheme.upper()})",
            "ioc_category": "URL",
            "value": val,
            "attributes": {
                "Scheme": parsed.scheme,
                "Hostname": parsed.netloc,
                "Path": parsed.path or "/",
                "Query": parsed.query or "(none)",
                "Embedded Credentials (@)": "@" in val,
            },
            "risk_assessment": "URL_SAFETY_ANALYSIS",
        }

    # 5. Domain Name Check
    if re.fullmatch(r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}", val):
        return {
            "valid": True,
            "type": "Domain Name",
            "ioc_category": "DOMAIN",
            "value": val,
            "attributes": {
                "Domain Name": val,
                "Subdomain Count": val.count(".") - 1,
                "Top-Level Domain (TLD)": val.split(".")[-1],
                "Excessive Hyphens": val.count("-") > 2,
            },
            "risk_assessment": "DOMAIN_REPUTATION_CHECK",
        }

    return {"valid": False, "error": "Unrecognized IOC structure. Enter a valid IP, Domain, URL, Hash, or Email."}


def render():
    page_header(
        "IOC (Indicator of Compromise) Analyzer",
        "Automated defensive identification, classification, and reputation lookup for security artifacts.",
        "🔎",
    )

    st.markdown(
        """
        An **Indicator of Compromise (IOC)** is an artifact observed on a network or operating system that, 
        with high confidence, indicates a computer intrusion or security incident.
        """
    )

    ioc_input = st.text_input(
        "Enter Indicator of Compromise (IP, Domain, URL, Hash, or Email)",
        placeholder="e.g. 8.8.8.8, e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855, or http://suspicious.site",
        key="ioc_input_field",
    )

    if st.button("Analyze IOC", key="btn_run_ioc"):
        if not ioc_input:
            st.error("Please enter an IOC to analyze.")
            return

        result = classify_ioc(ioc_input)
        if not result["valid"]:
            st.error(f"❌ {result['error']}")
            return

        record_activity(f"IOC analyzed: {result['value']} ({result['type']})", "general")
        log_event("IOC_ANALYSIS", f"Analyzed {result['type']}: {result['value']}", "INFO")

        col1, col2 = st.columns(2)
        with col1:
            st.metric("Detected IOC Type", result["type"])
        with col2:
            st.metric("Classification", result["risk_assessment"].replace("_", " "))

        st.markdown(
            f"""
            <div class="result-card">
                <h4 style="color:#6ee7b7;">IOC Attribute Inspection</h4>
                <p><strong>Raw Value:</strong> <code>{result['value']}</code></p>
                <p><strong>Category:</strong> {result['ioc_category']}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.subheader("Attributes")
        st.json(result["attributes"])

        # VirusTotal Integration for Hash IOCs
        if result["ioc_category"] == "HASH" and len(result["value"]) == 64:
            api_key = get_api_key()
            if api_key:
                st.subheader("VirusTotal Threat Intelligence Lookup")
                vt_res = check_existing_report(result["value"], api_key)
                if vt_res["success"] and vt_res.get("found"):
                    st.success("✅ Match found in VirusTotal Database!")
                    stats = vt_res["data"].get("attributes", {}).get("last_analysis_stats", {})
                    st.write("Last Analysis Stats:", stats)
                    malicious = stats.get("malicious", 0)
                    if malicious > 0:
                        add_finding(
                            title=f"Malicious SHA-256 IOC Flagged: {result['value'][:12]}...",
                            severity="HIGH" if malicious >= 3 else "MEDIUM",
                            score=75,
                            explanation=f"SHA-256 hash IOC flagged by {malicious} security engines on VirusTotal.",
                            recommendation="Isolate endpoint and block file hash execution in endpoint control systems.",
                            source_tool="IOC Analyzer",
                            mitre_tactic="Execution",
                            mitre_technique="T1204 — User Execution",
                        )
                elif vt_res["success"] and not vt_res.get("found"):
                    st.info("No pre-computed report found on VirusTotal for this SHA-256 hash.")
                else:
                    st.warning(f"VirusTotal lookup error: {vt_res.get('error')}")

        st.info("🔒 Defensive Guarantee: This tool only performs passive classification and lookup. No offensive actions or port scanning are conducted.")
