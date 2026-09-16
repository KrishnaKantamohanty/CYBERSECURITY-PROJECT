import io
import struct
import datetime
import socket
import streamlit as st
from utils.theme import page_header
from utils.security import record_activity
from modules.security_events import log_event
from modules.risk_engine import add_finding


# =============================================================================
# PURE PYTHON PCAP PARSER & DISSECTOR
# =============================================================================

def parse_pcap_bytes(pcap_data: bytes) -> dict:
    """
    Parse raw PCAP file bytes into structured packet objects.
    Supports standard microsecond and nanosecond libpcap file formats.
    """
    if len(pcap_data) < 24:
        return {"valid": False, "error": "File too small to be a valid PCAP."}

    magic = struct.unpack("<I", pcap_data[:4])[0]
    little_endian = True

    if magic == 0xA1B2C3D4:  # Standard microsecond PCAP (little-endian)
        little_endian = True
    elif magic == 0xD4C3B2A1:  # Standard microsecond PCAP (big-endian)
        little_endian = False
    elif magic == 0xA1B23C4D:  # Nanosecond PCAP (little-endian)
        little_endian = True
    elif magic == 0x4D3CB2A1:  # Nanosecond PCAP (big-endian)
        little_endian = False
    else:
        return {
            "valid": False,
            "error": f"Unsupported or invalid PCAP magic header (0x{magic:08x}). Please upload a standard .pcap file.",
        }

    endian_prefix = "<" if little_endian else ">"
    global_hdr = struct.unpack(f"{endian_prefix}IHHIIII", pcap_data[:24])
    version_major = global_hdr[1]
    version_minor = global_hdr[2]
    snaplen = global_hdr[5]
    linktype = global_hdr[6]  # 1 = Ethernet

    offset = 24
    packets = []
    packet_num = 1
    first_ts = None

    while offset + 16 <= len(pcap_data):
        pkt_hdr = struct.unpack(f"{endian_prefix}IIII", pcap_data[offset : offset + 16])
        ts_sec, ts_usec, incl_len, orig_len = pkt_hdr
        offset += 16

        if offset + incl_len > len(pcap_data):
            break  # Truncated trailing packet

        raw_frame = pcap_data[offset : offset + incl_len]
        offset += incl_len

        if first_ts is None:
            first_ts = ts_sec + (ts_usec / 1_000_000.0)

        rel_time = (ts_sec + (ts_usec / 1_000_000.0)) - first_ts

        parsed_pkt = _dissect_frame(raw_frame, packet_num, rel_time, linktype)
        packets.append(parsed_pkt)
        packet_num += 1

        if len(packets) >= 2000:
            break  # Safety ceiling for in-memory browser analysis

    return {
        "valid": True,
        "magic": f"0x{magic:08x}",
        "version": f"{version_major}.{version_minor}",
        "snaplen": snaplen,
        "linktype": linktype,
        "total_packets": len(packets),
        "packets": packets,
    }


def _dissect_frame(raw: bytes, pkt_num: int, rel_time: float, linktype: int) -> dict:
    """Dissect Ethernet -> IP -> Transport -> Application layers."""
    pkt = {
        "num": pkt_num,
        "time": round(rel_time, 4),
        "len": len(raw),
        "src_mac": "N/A",
        "dst_mac": "N/A",
        "src_ip": "N/A",
        "dst_ip": "N/A",
        "src_port": None,
        "dst_port": None,
        "protocol": "Raw/Unknown",
        "info": "",
        "flags": "",
        "layers": {},
        "raw_hex": raw[:128].hex(),
        "payload_text": "",
        "security_flags": [],
    }

    payload = raw

    # 1. Link Layer (Ethernet)
    if linktype == 1 and len(raw) >= 14:
        dst_mac = ":".join(f"{b:02x}" for b in raw[0:6])
        src_mac = ":".join(f"{b:02x}" for b in raw[6:12])
        ethertype = struct.unpack("!H", raw[12:14])[0]
        pkt["src_mac"] = src_mac
        pkt["dst_mac"] = dst_mac
        pkt["layers"]["Ethernet"] = {"src": src_mac, "dst": dst_mac, "ethertype": f"0x{ethertype:04x}"}
        payload = raw[14:]

        if ethertype == 0x0806:  # ARP
            pkt["protocol"] = "ARP"
            pkt["info"] = "Address Resolution Protocol (ARP)"
            return pkt
        elif ethertype != 0x0800:  # Not IPv4
            pkt["protocol"] = f"EtherType 0x{ethertype:04x}"
            return pkt

    # 2. Network Layer (IPv4)
    if len(payload) >= 20:
        ver_ihl = payload[0]
        version = ver_ihl >> 4
        ihl = (ver_ihl & 0x0F) * 4
        if version == 4 and len(payload) >= ihl:
            total_len, ident, flags_fo, ttl, proto_num = struct.unpack("!HHHBB", payload[2:10])
            src_ip = socket.inet_ntoa(payload[12:16])
            dst_ip = socket.inet_ntoa(payload[16:20])
            pkt["src_ip"] = src_ip
            pkt["dst_ip"] = dst_ip
            pkt["layers"]["IPv4"] = {
                "version": 4,
                "ihl": ihl,
                "ttl": ttl,
                "protocol_num": proto_num,
                "src": src_ip,
                "dst": dst_ip,
            }
            ip_payload = payload[ihl:]

            # 3. Transport Layer
            if proto_num == 6 and len(ip_payload) >= 20:  # TCP
                src_p, dst_p, seq, ack, offset_flags, win = struct.unpack("!HHIIHH", ip_payload[:16])
                data_offset = (offset_flags >> 12) * 4
                tcp_flags_val = offset_flags & 0x01FF

                flag_strs = []
                if tcp_flags_val & 0x02: flag_strs.append("SYN")
                if tcp_flags_val & 0x10: flag_strs.append("ACK")
                if tcp_flags_val & 0x01: flag_strs.append("FIN")
                if tcp_flags_val & 0x04: flag_strs.append("RST")
                if tcp_flags_val & 0x08: flag_strs.append("PSH")
                if tcp_flags_val & 0x20: flag_strs.append("URG")

                pkt["protocol"] = "TCP"
                pkt["src_port"] = src_p
                pkt["dst_port"] = dst_p
                pkt["flags"] = ",".join(flag_strs)
                pkt["info"] = f"{src_p} → {dst_p} [{pkt['flags']}] Seq={seq} Win={win}"
                pkt["layers"]["TCP"] = {
                    "src_port": src_p,
                    "dst_port": dst_p,
                    "seq": seq,
                    "ack": ack,
                    "flags": pkt["flags"],
                    "window": win,
                }

                app_data = ip_payload[data_offset:]
                if app_data:
                    _dissect_application_layer(app_data, src_p, dst_p, pkt)

            elif proto_num == 17 and len(ip_payload) >= 8:  # UDP
                src_p, dst_p, u_len, u_chk = struct.unpack("!HHHH", ip_payload[:8])
                pkt["protocol"] = "UDP"
                pkt["src_port"] = src_p
                pkt["dst_port"] = dst_p
                pkt["info"] = f"{src_p} → {dst_p} Len={u_len}"
                pkt["layers"]["UDP"] = {"src_port": src_p, "dst_port": dst_p, "len": u_len}

                app_data = ip_payload[8:]
                if app_data:
                    _dissect_application_layer(app_data, src_p, dst_p, pkt)

            elif proto_num == 1 and len(ip_payload) >= 4:  # ICMP
                icmp_type, icmp_code = struct.unpack("!BB", ip_payload[:2])
                pkt["protocol"] = "ICMP"
                type_desc = "Echo (ping) Request" if icmp_type == 8 else ("Echo (ping) Reply" if icmp_type == 0 else f"Type {icmp_type}")
                pkt["info"] = f"ICMP {type_desc} (code {icmp_code})"
                pkt["layers"]["ICMP"] = {"type": icmp_type, "code": icmp_code, "desc": type_desc}

    return pkt


def _dissect_application_layer(app_data: bytes, src_p: int, dst_p: int, pkt: dict):
    """Detect DNS, HTTP, TLS, Telnet, or plaintext payloads."""
    # Text snippet representation
    printable_text = "".join(chr(b) if 32 <= b <= 126 else "." for b in app_data[:256])
    pkt["payload_text"] = printable_text

    # DNS Detection (Port 53 or DNS header format)
    if src_p == 53 or dst_p == 53:
        pkt["protocol"] = "DNS"
        if len(app_data) >= 12:
            tx_id, flags, q_count, a_count = struct.unpack("!HHHH", app_data[:8])
            qname = _parse_dns_qname(app_data[12:])
            is_response = bool(flags & 0x8000)
            pkt["info"] = f"Standard query response for {qname}" if is_response else f"Standard query for {qname}"
            pkt["layers"]["DNS"] = {"tx_id": f"0x{tx_id:04x}", "query": qname, "is_response": is_response}
            return

    # HTTP Detection
    http_methods = [b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"HTTP/1.1", b"HTTP/1.0"]
    if any(app_data.startswith(m) for m in http_methods) or src_p in [80, 8080] or dst_p in [80, 8080]:
        if any(app_data.startswith(m) for m in http_methods):
            pkt["protocol"] = "HTTP"
            first_line = app_data.split(b"\r\n")[0].decode("latin-1", errors="ignore")
            pkt["info"] = first_line[:60]
            pkt["layers"]["HTTP"] = {"request_line": first_line}

            # Security Inspection: Check for unencrypted credentials
            lower_text = app_data.lower()
            if b"password=" in lower_text or b"passwd=" in lower_text or b"authorization: basic" in lower_text:
                pkt["security_flags"].append("UNENCRYPTED_CREDENTIALS")

    # TLS Handshake Detection (Port 443 or TLS record 0x16 0x03)
    elif src_p == 443 or dst_p == 443 or (len(app_data) >= 3 and app_data[0] == 0x16 and app_data[1] == 0x03):
        pkt["protocol"] = "HTTPS/TLS"
        if app_data[0] == 0x16:
            pkt["info"] = "TLS Encrypted Handshake Record"
        else:
            pkt["info"] = "TLS Application Data (Encrypted)"

    # Telnet Detection
    elif src_p == 23 or dst_p == 23:
        pkt["protocol"] = "Telnet"
        pkt["info"] = "Unencrypted Telnet Session Stream"
        pkt["security_flags"].append("PLAINTEXT_TELNET")

    # FTP Detection
    elif src_p == 21 or dst_p == 21:
        pkt["protocol"] = "FTP"
        line = app_data.split(b"\r\n")[0].decode("latin-1", errors="ignore")
        pkt["info"] = f"FTP: {line}"
        if line.startswith(("USER ", "PASS ")):
            pkt["security_flags"].append("PLAINTEXT_FTP_AUTH")


def _parse_dns_qname(data: bytes) -> str:
    """Extract domain name from DNS query labels."""
    labels = []
    idx = 0
    while idx < len(data):
        length = data[idx]
        if length == 0 or length > 63:
            break
        idx += 1
        label = data[idx : idx + length].decode("ascii", errors="ignore")
        labels.append(label)
        idx += length
    return ".".join(labels) if labels else "unknown-domain"


# =============================================================================
# SYNTHETIC EDUCATIONAL PCAP GENERATOR
# =============================================================================

def generate_sample_educational_pcap() -> bytes:
    """
    Generate an educational synthetic PCAP capture file containing:
    1. DNS query & response for 'login.internal-corp.net'
    2. Insecure HTTP POST with cleartext password
    3. Simulated Port Scan (SYN probes)
    4. Encrypted TLS Session (HTTPS)
    5. ICMP Ping exchange
    """
    buf = io.BytesIO()
    # PCAP Global Header: Magic(microsec, LE), v2.4, thiszone=0, sigfigs=0, snaplen=65535, linktype=1 (Ethernet)
    buf.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

    ts = 1700000000
    usec = 100000

    def write_pkt(raw_bytes: bytes, delta_ms: int = 150):
        nonlocal ts, usec
        usec += delta_ms * 1000
        if usec >= 1_000_000:
            ts += 1
            usec %= 1_000_000
        p_hdr = struct.pack("<IIII", ts, usec, len(raw_bytes), len(raw_bytes))
        buf.write(p_hdr)
        buf.write(raw_bytes)

    # Helper: Build Ethernet + IPv4 + UDP/TCP
    def make_eth_ip(proto_num, src_ip, dst_ip, payload_bytes):
        src_mac = b"\x00\x0c\x29\x4f\x8e\x12"
        dst_mac = b"\x00\x50\x56\xc0\x00\x08"
        eth = dst_mac + src_mac + struct.pack("!H", 0x0800)
        
        src_b = socket.inet_aton(src_ip)
        dst_b = socket.inet_aton(dst_ip)
        total_len = 20 + len(payload_bytes)
        ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, 1001, 0x4000, 64, proto_num, 0, src_b, dst_b)
        return eth + ip_hdr + payload_bytes

    # 1. DNS Query for login.internal-corp.net
    dns_q = struct.pack("!HHHHHH", 0x1A2B, 0x0100, 1, 0, 0, 0) + b"\x05login\x0dinternal-corp\x03net\x00\x00\x01\x00\x01"
    udp_dns = struct.pack("!HHHH", 52140, 53, len(dns_q) + 8, 0) + dns_q
    write_pkt(make_eth_ip(17, "192.168.1.50", "8.8.8.8", udp_dns), 50)

    # 2. Insecure HTTP POST containing cleartext credentials
    http_payload = (
        b"POST /api/v1/auth HTTP/1.1\r\n"
        b"Host: login.internal-corp.net\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: 42\r\n\r\n"
        b"username=admin&password=SuperSecretPassword2026!"
    )
    tcp_http = struct.pack("!HHIIHH", 49152, 80, 1000, 1, (5 << 12) | 0x018, 65535) + struct.pack("!HH", 0, 0) + http_payload
    write_pkt(make_eth_ip(6, "192.168.1.50", "192.168.1.100", tcp_http), 120)

    # 3. Simulated Port Scan (SYN packets to ports 21, 22, 23, 445, 3389)
    for p in [21, 22, 23, 445, 3389]:
        tcp_syn = struct.pack("!HHIIHH", 54321, p, 100 + p, 0, (5 << 12) | 0x002, 1024) + struct.pack("!HH", 0, 0)
        write_pkt(make_eth_ip(6, "10.0.0.88", "192.168.1.100", tcp_syn), 40)

    # 4. HTTPS / TLS Handshake
    tls_data = b"\x16\x03\x01\x00\x40" + (b"\x01" * 64)
    tcp_tls = struct.pack("!HHIIHH", 49200, 443, 5000, 200, (5 << 12) | 0x018, 65535) + struct.pack("!HH", 0, 0) + tls_data
    write_pkt(make_eth_ip(6, "192.168.1.50", "142.250.190.46", tcp_tls), 200)

    # 5. ICMP Ping Request & Reply
    icmp_req = struct.pack("!BBHHH", 8, 0, 0, 0x1234, 1) + b"abcdefghijklmnopqrstuvw"
    write_pkt(make_eth_ip(1, "192.168.1.50", "1.1.1.1", icmp_req), 30)
    icmp_rep = struct.pack("!BBHHH", 0, 0, 0, 0x1234, 1) + b"abcdefghijklmnopqrstuvw"
    write_pkt(make_eth_ip(1, "1.1.1.1", "192.168.1.50", icmp_rep), 25)

    return buf.getvalue()


# =============================================================================
# STREAMLIT UI RENDERER
# =============================================================================

def render():
    page_header(
        "Basic Packet Analyzer & Traffic Inspector",
        "Inspect network packet captures (.pcap), analyze protocol distributions, and detect cleartext traffic anomalies.",
        "📡",
    )

    if "pcap_analysis_result" not in st.session_state:
        st.session_state.pcap_analysis_result = None

    tab_load, tab_stats, tab_packets, tab_threats = st.tabs([
        "📂 PCAP Capture Loader",
        "📊 Protocol & Traffic Analytics",
        "🔍 Packet Dissector & Filter",
        "🚨 Security Threat Inspector",
    ])

    # -------------------------------------------------------------------------
    # TAB 1: PCAP Capture Loader
    # -------------------------------------------------------------------------
    with tab_load:
        st.subheader("Load Network Packet Capture")
        st.caption("Upload an existing `.pcap` capture file or generate a synthetic capture to analyze.")

        col_up, col_sample = st.columns([2, 1])
        with col_up:
            uploaded_pcap = st.file_uploader(
                "Upload .pcap capture file (Max 15MB)",
                type=["pcap", "cap"],
                key="pcap_file_uploader",
            )
            if uploaded_pcap:
                if st.button("Parse Uploaded PCAP", key="btn_parse_pcap", type="primary"):
                    with st.spinner("Dissecting network packets..."):
                        pcap_bytes = uploaded_pcap.getvalue()
                        res = parse_pcap_bytes(pcap_bytes)
                        if res["valid"]:
                            st.session_state.pcap_analysis_result = res
                            st.session_state.pcap_filename = uploaded_pcap.name
                            record_activity(f"PCAP analyzed: {uploaded_pcap.name} ({res['total_packets']} packets)", "network")
                            log_event("PCAP_ANALYSIS", f"Dissected {res['total_packets']} packets from {uploaded_pcap.name}", "INFO")
                            st.success(f"✅ Dissected {res['total_packets']} packets successfully!")
                            st.rerun()
                        else:
                            st.error(f"❌ {res['error']}")

        with col_sample:
            st.markdown(
                """
                <div style="background:rgba(255,255,255,0.03); border:1px solid rgba(0,255,255,0.15); padding:16px; border-radius:8px;">
                    <h4 style="margin:0 0 8px 0; color:#6ee7b7;">🧪 Educational Demo</h4>
                    <p style="font-size:0.85rem; opacity:0.85; margin:0 0 12px 0;">
                        Generate a simulated trace with DNS, unencrypted HTTP login, SYN port scanning, and TLS traffic.
                    </p>
                </div>
                """,
                unsafe_allow_html=True,
            )
            if st.button("⚡ Load Sample PCAP", key="btn_load_sample_pcap"):
                with st.spinner("Generating educational packet trace..."):
                    sample_bytes = generate_sample_educational_pcap()
                    res = parse_pcap_bytes(sample_bytes)
                    st.session_state.pcap_analysis_result = res
                    st.session_state.pcap_filename = "sample_educational_trace.pcap"
                    record_activity("Sample educational PCAP loaded", "network")
                    log_event("PCAP_ANALYSIS", "Loaded synthetic educational capture trace", "INFO")
                    st.success("✅ Sample capture trace loaded successfully!")
                    st.rerun()

        # Display Active PCAP Overview Card
        if st.session_state.pcap_analysis_result:
            res = st.session_state.pcap_analysis_result
            st.markdown("---")
            st.markdown(
                f"""
                <div class="result-card">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <div>
                            <h4 style="margin:0; color:#6ee7b7;">Active Capture: {st.session_state.get('pcap_filename', 'capture.pcap')}</h4>
                            <p style="margin:4px 0 0 0; opacity:0.8; font-size:0.85rem;">
                                Format: Libpcap v{res['version']} | Link Type: Ethernet ({res['linktype']}) | SnapLen: {res['snaplen']} bytes
                            </p>
                        </div>
                        <div class="badge-very-strong">
                            {res['total_packets']} PACKETS LOADED
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    # -------------------------------------------------------------------------
    # TAB 2: Protocol & Traffic Analytics
    # -------------------------------------------------------------------------
    with tab_stats:
        if not st.session_state.pcap_analysis_result:
            st.info("💡 Please load or upload a PCAP capture in the **PCAP Capture Loader** tab to view analytics.")
        else:
            res = st.session_state.pcap_analysis_result
            packets = res["packets"]

            # Aggregate stats
            proto_counts = {}
            src_ips = {}
            dst_ips = {}
            total_bytes = 0

            for p in packets:
                proto = p["protocol"]
                proto_counts[proto] = proto_counts.get(proto, 0) + 1
                total_bytes += p["len"]
                if p["src_ip"] != "N/A":
                    src_ips[p["src_ip"]] = src_ips.get(p["src_ip"], 0) + 1
                if p["dst_ip"] != "N/A":
                    dst_ips[p["dst_ip"]] = dst_ips.get(p["dst_ip"], 0) + 1

            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Total Packets", str(len(packets)))
            m2.metric("Total Data Volume", f"{total_bytes / 1024:.2f} KB")
            m3.metric("Unique Protocols", str(len(proto_counts)))
            m4.metric("Unique IP Endpoints", str(len(set(list(src_ips.keys()) + list(dst_ips.keys())))))

            st.markdown("---")

            col_p1, col_p2 = st.columns(2)
            with col_p1:
                st.subheader("Protocol Distribution")
                proto_table = [{"Protocol": k, "Packet Count": v, "Share": f"{(v / len(packets)) * 100:.1f}%"} for k, v in sorted(proto_counts.items(), key=lambda x: x[1], reverse=True)]
                st.table(proto_table)

            with col_p2:
                st.subheader("Top Communicating Hosts")
                talkers = []
                all_ips = set(list(src_ips.keys()) + list(dst_ips.keys()))
                for ip in all_ips:
                    s_c = src_ips.get(ip, 0)
                    d_c = dst_ips.get(ip, 0)
                    talkers.append({"Host IP": ip, "Sent Packets": s_c, "Received Packets": d_c, "Total": s_c + d_c})
                talkers.sort(key=lambda x: x["Total"], reverse=True)
                st.dataframe(talkers[:10], use_container_width=True, hide_index=True)

    # -------------------------------------------------------------------------
    # TAB 3: Packet Dissector & Filter
    # -------------------------------------------------------------------------
    with tab_packets:
        if not st.session_state.pcap_analysis_result:
            st.info("💡 Please load a PCAP file in the first tab to inspect packet streams.")
        else:
            res = st.session_state.pcap_analysis_result
            packets = res["packets"]

            # Filter row
            col_f1, col_f2 = st.columns([1, 2])
            with col_f1:
                avail_protos = ["All"] + sorted(list(set(p["protocol"] for p in packets)))
                sel_proto = st.selectbox("Filter by Protocol", avail_protos, key="sel_proto_filter")
            with col_f2:
                search_query = st.text_input("Search IP, Port, or Keyword", placeholder="e.g. 192.168.1.50 or login", key="pcap_search_query")

            filtered_pkts = packets
            if sel_proto != "All":
                filtered_pkts = [p for p in filtered_pkts if p["protocol"] == sel_proto]
            if search_query:
                sq = search_query.lower()
                filtered_pkts = [
                    p for p in filtered_pkts
                    if sq in p["src_ip"].lower() or sq in p["dst_ip"].lower() or sq in str(p["src_port"]) or sq in str(p["dst_port"]) or sq in p["info"].lower() or sq in p["payload_text"].lower()
                ]

            st.caption(f"Showing {len(filtered_pkts)} of {len(packets)} packets")

            # Display table
            display_list = []
            for p in filtered_pkts[:100]:
                src_ep = f"{p['src_ip']}:{p['src_port']}" if p.get("src_port") else p["src_ip"]
                dst_ep = f"{p['dst_ip']}:{p['dst_port']}" if p.get("dst_port") else p["dst_ip"]
                display_list.append({
                    "#": p["num"],
                    "Time (s)": p["time"],
                    "Source": src_ep,
                    "Destination": dst_ep,
                    "Protocol": p["protocol"],
                    "Length": f"{p['len']} B",
                    "Info": p["info"],
                })
            st.dataframe(display_list, use_container_width=True, hide_index=True)

            # Deep Packet Inspector Expander
            st.markdown("---")
            st.subheader("Deep Packet Header & Payload Inspector")
            pkt_choice_num = st.number_input(
                "Select Packet # to Inspect",
                min_value=1,
                max_value=len(packets),
                value=min(2, len(packets)),
                key="inspect_pkt_choice",
            )

            selected_pkt = next((p for p in packets if p["num"] == pkt_choice_num), None)
            if selected_pkt:
                st.markdown(
                    f"""
                    <div class="result-card">
                        <h4 style="color:#6ee7b7; margin:0 0 6px 0;">Packet #{selected_pkt['num']} — {selected_pkt['protocol']} Layer Breakdown</h4>
                        <p style="margin:0; font-size:0.85rem; opacity:0.85;">
                            Timestamp: +{selected_pkt['time']}s | Total Frame Length: {selected_pkt['len']} bytes
                        </p>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                st.json(selected_pkt["layers"])

                if selected_pkt["payload_text"]:
                    st.markdown("#### Payload ASCII Representation")
                    st.code(selected_pkt["payload_text"], language="text")

                st.markdown("#### Raw Hex Dump (First 128 Bytes)")
                st.code(selected_pkt["raw_hex"], language="text")

    # -------------------------------------------------------------------------
    # TAB 4: Security Threat Inspector
    # -------------------------------------------------------------------------
    with tab_threats:
        if not st.session_state.pcap_analysis_result:
            st.info("💡 Please load a PCAP file to inspect for security threats and cleartext transmissions.")
        else:
            res = st.session_state.pcap_analysis_result
            packets = res["packets"]

            st.subheader("Security & Cleartext Vulnerability Audit")
            st.caption("Automated heuristic engine detecting unencrypted credentials, network scans, and reconnaissance behavior in packet flows.")

            threats_found = []

            # 1. Cleartext credentials inspection
            cleartext_pkts = [p for p in packets if "UNENCRYPTED_CREDENTIALS" in p["security_flags"] or "PLAINTEXT_FTP_AUTH" in p["security_flags"] or "PLAINTEXT_TELNET" in p["security_flags"]]
            if cleartext_pkts:
                threats_found.append({
                    "title": "Plaintext Credentials Transmitted Over Network",
                    "severity": "CRITICAL",
                    "score": 90,
                    "desc": f"Found {len(cleartext_pkts)} packet(s) transmitting unencrypted passwords or authentication commands (HTTP / FTP / Telnet).",
                    "recommendation": "Enforce HTTPS/TLS encryption and migrate from legacy plaintext protocols to SSH and SFTP.",
                    "packets": [p["num"] for p in cleartext_pkts],
                    "mitre_tactic": "Credential Access",
                    "mitre_technique": "T1040 — Network Sniffing",
                })

            # 2. Port scan detection (Multiple SYN packets to distinct destination ports from same source)
            syn_pkts = [p for p in packets if p.get("flags") == "SYN"]
            syn_sources = {}
            for sp in syn_pkts:
                src = sp["src_ip"]
                dst = sp["dst_ip"]
                dst_p = sp["dst_port"]
                syn_sources.setdefault(src, set()).add((dst, dst_p))

            for src, targets in syn_sources.items():
                if len(targets) >= 4:
                    threats_found.append({
                        "title": f"Potential Network Port Scan Detected from {src}",
                        "severity": "HIGH",
                        "score": 75,
                        "desc": f"Host {src} sent SYN probe packets to {len(targets)} distinct ports across the network within the trace.",
                        "recommendation": "Implement intrusion prevention (IPS/IDS) rate limiting and drop unauthorized scanning sources at boundary firewalls.",
                        "packets": [p["num"] for p in syn_pkts if p["src_ip"] == src],
                        "mitre_tactic": "Discovery",
                        "mitre_technique": "T1046 — Network Service Discovery",
                    })

            # 3. DNS queries to non-standard or suspicious lookups
            dns_pkts = [p for p in packets if p["protocol"] == "DNS" and "DNS" in p.get("layers", {})]
            if dns_pkts:
                queries = [p["layers"]["DNS"]["query"] for p in dns_pkts]
                st.info(f"ℹ️ Audited {len(dns_pkts)} DNS queries in capture: `{', '.join(set(queries))}`")

            # Display Threat Findings
            if threats_found:
                for tf in threats_found:
                    sev_color = "#ef4444" if tf["severity"] == "CRITICAL" else "#f97316"
                    st.markdown(
                        f"""
                        <div style="background:rgba(255,255,255,0.03); border-left: 4px solid {sev_color}; border-top:1px solid rgba(255,255,255,0.08); border-right:1px solid rgba(255,255,255,0.08); border-bottom:1px solid rgba(255,255,255,0.08); padding:14px 18px; border-radius:6px; margin-bottom:12px;">
                            <div style="display:flex; justify-content:space-between; align-items:center;">
                                <strong style="font-size:1.15rem; color:{sev_color};">🚨 {tf['title']}</strong>
                                <span style="background:{sev_color}22; color:{sev_color}; padding:4px 10px; border-radius:12px; font-weight:700; font-size:0.8rem; border:1px solid {sev_color}44;">
                                    {tf['severity']}
                                </span>
                            </div>
                            <p style="margin:8px 0 6px 0; font-size:0.95rem; opacity:0.9;">{tf['desc']}</p>
                            <p style="margin:0 0 4px 0; font-size:0.85rem; color:#93c5fd;"><strong>MITRE ATT&CK:</strong> {tf['mitre_tactic']} ({tf['mitre_technique']})</p>
                            <p style="margin:0; font-size:0.88rem; color:#6ee7b7;"><strong>Remediation:</strong> {tf['recommendation']}</p>
                            <p style="margin:6px 0 0 0; font-size:0.8rem; opacity:0.7;">Flagged Packets: {', '.join(f'#{n}' for n in tf['packets'])}</p>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                if st.button("📥 Sync Findings to Central Risk Engine", key="btn_sync_pcap_risks", type="primary"):
                    for tf in threats_found:
                        add_finding(
                            title=tf["title"],
                            severity=tf["severity"],
                            score=tf["score"],
                            explanation=tf["desc"],
                            recommendation=tf["recommendation"],
                            source_tool="Packet Analyzer",
                            mitre_tactic=tf["mitre_tactic"],
                            mitre_technique=tf["mitre_technique"],
                        )
                    st.success("✅ Threat findings synced to Security Center & Risk Engine!")
            else:
                st.success("✅ **No severe traffic anomalies or cleartext credential leaks detected in this capture.**")
