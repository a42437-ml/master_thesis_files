#!/usr/bin/env python3
import scapy.all as scapy
import logging
import csv
import re
from datetime import datetime

# Logging
logging.basicConfig(level=logging.INFO)

# PCAP file path
pcap_file = "/var/log/suricata/log.pcap.1748170921"

# Helper to extract tag= param
def extract_tag(line):
    match = re.search(r'tag=([\w\d\-\.]+)', line, re.IGNORECASE)
    return match.group(1) if match else ""

# State tracking
callid_states = {}

# Read packets
packets = scapy.rdpcap(pcap_file)

# Output CSV
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
csv_filename = f"sip_features_{timestamp}.csv"

# Static headers (including dynamic fields as static!)
fieldnames = [
    "src_ip", "dst_ip", "message_type", "call_completion_status", "call_duration_sec",
    "Via", "From", "From_tag", "To", "To_tag", "Call-ID", "CSeq", "Contact",
    "X-", "Subject", "Max-Forwards", "Content-Type", "v", "o", "s", "t", "m", "a", "User-Agent",
    "Identity", "Attestation-Level", "Origination-ID", "boundary", "smime signature"
]

rows = []

for pkt in packets:
    if pkt.haslayer(scapy.UDP) and (pkt[scapy.UDP].dport in range(5060, 5101) or pkt[scapy.UDP].sport in range(5060, 5101)):
        try:
            payload = bytes(pkt[scapy.UDP].payload).decode('utf-8', errors='ignore')
            lines = payload.splitlines()
            if not lines:
                continue
            first_line = lines[0]

            # Initialize row with static fields
            row = {field: "" for field in fieldnames}
            row["src_ip"] = pkt[scapy.IP].src
            row["dst_ip"] = pkt[scapy.IP].dst

            # Message type
            if first_line.startswith("INVITE"):
                row["message_type"] = "INVITE"
            elif first_line.startswith("OPTIONS"):
                row["message_type"] = "OPTIONS"
            elif first_line.startswith("BYE"):
                row["message_type"] = "BYE"
            elif first_line.startswith("ACK"):
                row["message_type"] = "ACK"
            elif first_line.startswith("SIP/2.0 100"):
                row["message_type"] = "100 Trying"
            elif first_line.startswith("SIP/2.0 180"):
                row["message_type"] = "180 Ringing"
            elif first_line.startswith("SIP/2.0 200"):
                row["message_type"] = "200 OK"

            boundary = None
            in_multipart = False
            multipart_data = {}
            current_part = None

            # Parse headers
            for line in lines:
                lower_line = line.lower()
                if lower_line.startswith("via:"):
                    row["Via"] = line.strip()
                elif lower_line.startswith("from:"):
                    row["From"] = line.strip()
                    row["From_tag"] = extract_tag(line)
                elif lower_line.startswith("to:"):
                    row["To"] = line.strip()
                    row["To_tag"] = extract_tag(line)
                elif lower_line.startswith("call-id:"):
                    row["Call-ID"] = line.split(":", 1)[1].strip()
                elif lower_line.startswith("cseq:"):
                    row["CSeq"] = line.strip()
                elif lower_line.startswith("contact:"):
                    row["Contact"] = line.strip()
                elif lower_line.startswith("x-"):
                    row["X-"] = line.strip()
                elif lower_line.startswith("subject:"):
                    row["Subject"] = line.strip()
                elif lower_line.startswith("max-forwards:"):
                    row["Max-Forwards"] = line.strip()
                elif lower_line.startswith("content-type:"):
                    row["Content-Type"] = line.strip()
                    if "multipart" in lower_line:
                        in_multipart = True
                        # Extract boundary
                        boundary_match = re.search(r'boundary="?([^";]+)"?', line, re.IGNORECASE)
                        if boundary_match:
                            boundary = boundary_match.group(1)
                            row["boundary"] = boundary
                elif lower_line.startswith("user-agent:"):
                    row["User-Agent"] = line.strip()
                elif lower_line.startswith("v="):
                    row["v"] = line.strip()
                elif lower_line.startswith("o="):
                    row["o"] = line.strip()
                elif lower_line.startswith("s="):
                    row["s"] = line.strip()
                elif lower_line.startswith("t="):
                    row["t"] = line.strip()
                elif lower_line.startswith("m="):
                    # Concatenate multiple m= lines
                    if row["m"]:
                        row["m"] += " | " + line.strip()
                    else:
                        row["m"] = line.strip()
                elif lower_line.startswith("a="):
                    # Concatenate multiple a= lines
                    if row["a"]:
                        row["a"] += " | " + line.strip()
                    else:
                        row["a"] = line.strip()
                elif lower_line.startswith("identity:"):
                    row["Identity"] = line.strip()
                elif lower_line.startswith("attestation-level:"):
                    row["Attestation-Level"] = line.strip()
                elif lower_line.startswith("origination-id:"):
                    row["Origination-ID"] = line.strip()

            # If multipart, parse sections manually
            if in_multipart and boundary:
                # Join payload as string
                body = payload.split("\r\n\r\n", 1)[-1]  # skip headers
                parts = body.split("--" + boundary)
                for part in parts:
                    part_lines = part.strip().splitlines()
                    if not part_lines:
                        continue
                    # Check Content-Type of part
                    part_type = None
                    part_data = []
                    capture_data = False
                    for pl in part_lines:
                        pl_lower = pl.lower()
                        if pl_lower.startswith("content-type:"):
                            part_type = pl.split(":", 1)[1].strip()
                            if "application/pkcs7-signature" in pl_lower:
                                current_part = "smime signature"
                        elif pl_lower.startswith("content-length:"):
                            continue  # skip
                        elif pl == "":
                            # Empty line signals start of data
                            capture_data = True
                        elif capture_data:
                            part_data.append(pl.strip())
                    if current_part and part_data:
                        # Save S/MIME signature data as single line
                        row[current_part] = "".join(part_data)

            # State tracking
            call_id = row["Call-ID"]
            if call_id:
                if call_id not in callid_states:
                    callid_states[call_id] = {
                        "first_invite_time": None, "bye_time": None,
                        "has_invite": False, "has_bye": False,
                        "has_200ok": False, "has_options": False, "has_options_200ok": False
                    }
                state = callid_states[call_id]

                if row["message_type"] == "INVITE":
                    state["has_invite"] = True
                    state["first_invite_time"] = pkt.time
                elif row["message_type"] == "BYE":
                    state["has_bye"] = True
                    state["bye_time"] = pkt.time
                elif row["message_type"] == "OPTIONS":
                    state["has_options"] = True
                elif row["message_type"] == "200 OK":
                    if "OPTIONS" in row.get("CSeq", ""):
                        state["has_options_200ok"] = True
                    elif "INVITE" in row.get("CSeq", ""):
                        state["has_200ok"] = True

            rows.append({**row, "timestamp": pkt.time})

        except Exception as e:
            logging.warning(f"Error parsing packet: {e}")

# Final call statuses
for row in rows:
    state = callid_states.get(row["Call-ID"], {})
    if row["message_type"] == "INVITE":
        if state.get("has_invite") and state.get("has_200ok") and state.get("has_bye"):
            row["call_completion_status"] = "Complete"
            if state["first_invite_time"] and state["bye_time"]:
                row["call_duration_sec"] = round(state["bye_time"] - state["first_invite_time"], 2)
        else:
            row["call_completion_status"] = "Incomplete"
    elif row["message_type"] == "OPTIONS":
        if state.get("has_options") and state.get("has_options_200ok"):
            row["call_completion_status"] = "Complete (OPTIONS)"
        else:
            row["call_completion_status"] = "Incomplete (OPTIONS)"
    elif row["message_type"] == "200 OK" and state.get("has_options"):
        row["call_completion_status"] = "Complete (OPTIONS)" if state.get("has_options_200ok") else "Incomplete (OPTIONS)"
    elif row["message_type"] == "BYE":
        if state.get("has_invite") and state.get("has_200ok"):
            row["call_completion_status"] = "Complete"

# Sort rows
call_rows = [r for r in rows if r["message_type"] != "OPTIONS" and "OPTIONS" not in r.get("CSeq", "")]
options_rows = [r for r in rows if r["message_type"] == "OPTIONS" or ("OPTIONS" in r.get("CSeq", ""))]
rows_sorted = sorted(call_rows, key=lambda r: r["timestamp"]) + sorted(options_rows, key=lambda r: r["timestamp"])

# Write final CSV
with open(csv_filename, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    for r in rows_sorted:
        r.pop("timestamp", None)
        writer.writerow(r)

logging.info(f"Final SIP extraction done! Output: {csv_filename}")
