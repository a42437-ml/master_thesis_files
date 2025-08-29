# SIP Covert Channel Test Files

Repository for SIP-based covert channel feasibility testing - SIPp scenarios and packet captures.

## Structure

```
master_thesis_files/
├── README.md
│
├── sipp_scenarios/                    # All SIPp XML files
│   ├── TC-02.1_via_branch.xml        # Via branch parameter
│   ├── TC-02.2_max_forward.xml       # Max-Forward manipulation  
│   ├── TC-02.3_from_tag.xml          # From tag parameter
│   ├── TC-02.4_to_tag.xml            # To tag parameter
│   ├── TC-02.5_call_id.xml           # Call-ID modification
│   ├── TC-02.6_cseq.xml              # CSeq manipulation
│   ├── TC-02.7_contact.xml           # Contact header multiple params
│   ├── TC-02.8_user_agent.xml        # User-Agent header
│   ├── TC-02.9_organization.xml      # Organization header
│   ├── TC-02.10_reply_to.xml         # Reply-To header
│   ├── TC-02.11_call_info.xml        # Call-Info header
│   ├── TC-02.12_timestamp.xml        # Timestamp header
│   ├── TC-02.13_subject.xml          # Subject header
│   ├── TC-02.14_x_headers.xml        # Custom X-headers (VIABLE)
│   ├── TC-02.15_header_reorder.xml   # Header reordering
│   ├── TC-02.16_nonprint_chars.xml   # Non-printable characters
│   ├── TC-02.17_sip_options.xml      # SIP OPTIONS method
│   ├── TC-02.18_shaken_stir.xml      # SHAKEN/STIR headers (VIABLE)
│   ├── TC-02.19_session_headers.xml  # Session-ID, Trace-Info, Diversion
│   ├── TC-02.20_sdp_version.xml      # SDP version field
│   ├── TC-02.21_sdp_origin.xml       # SDP origin field
│   ├── TC-02.22_sdp_session_name.xml # SDP session name
│   ├── TC-02.23_sdp_time.xml         # SDP time active
│   ├── TC-02.24_sdp_encryption.xml   # SDP encryption key
│   ├── TC-02.25_sdp_session_info.xml # SDP session info
│   ├── TC-02.26_sdp_attributes.xml   # SDP attributes
│   ├── TC-02.27_sdp_media_desc.xml   # SDP media description (VIABLE)
│   ├── TC-02.28_smime_boundary.xml   # S/MIME boundary
│   └── TC-02.29_smime_signature.xml  # S/MIME signature (VIABLE)
│
└── pcap_files/                       # All packet captures
    ├── TC-02.1_via_branch.pcap       # Via branch test
    ├── TC-02.2_max_forward.pcap      # Max-Forward test
    ├── TC-02.3_from_tag.pcap         # From tag test
    ├── TC-02.4_to_tag.pcap           # To tag test
    ├── TC-02.5_call_id.pcap          # Call-ID test
    ├── TC-02.6_cseq.pcap             # CSeq test
    ├── TC-02.7_contact.pcap          # Contact header test
    ├── TC-02.8_user_agent.pcap       # User-Agent test
    ├── TC-02.9_organization.pcap     # Organization test
    ├── TC-02.10_reply_to.pcap        # Reply-To test
    ├── TC-02.11_call_info.pcap       # Call-Info test
    ├── TC-02.12_timestamp.pcap       # Timestamp test
    ├── TC-02.13_subject.pcap         # Subject test
    ├── TC-02.14_x_headers.pcap       # X-headers test (VIABLE)
    ├── TC-02.15_header_reorder.pcap  # Header reordering test
    ├── TC-02.16_nonprint_chars.pcap  # Non-printable chars test
    ├── TC-02.17_sip_options.pcap     # SIP OPTIONS test
    ├── TC-02.18_shaken_stir.pcap     # SHAKEN/STIR test (VIABLE)
    ├── TC-02.19_session_headers.pcap # Session headers test
    ├── TC-02.20_sdp_version.pcap     # SDP version test
    ├── TC-02.21_sdp_origin.pcap      # SDP origin test
    ├── TC-02.22_sdp_session_name.pcap# SDP session name test
    ├── TC-02.23_sdp_time.pcap        # SDP time test
    ├── TC-02.24_sdp_encryption.pcap  # SDP encryption test
    ├── TC-02.25_sdp_session_info.pcap# SDP session info test
    ├── TC-02.26_sdp_attributes.pcap  # SDP attributes test
    ├── TC-02.27_sdp_media_desc.pcap  # SDP media desc test (VIABLE)
    ├── TC-02.28_smime_boundary.pcap  # S/MIME boundary test
    └── TC-02.29_smime_signature.pcap # S/MIME signature test (VIABLE)
```

## Usage

**Run SIPp scenario:**
```bash
sipp -sf sipp_scenarios/TC-02.14_x_headers.xml [target_ip]
```

**Analyze with sngrep:**
```bash
sngrep -I pcap_files/TC-02.14_x_headers.pcap
```

**Analyze with Wireshark:**
```bash
wireshark pcap_files/TC-02.14_x_headers.pcap
```

### Key Findings

- **Total Tests**: 29 test cases covering SIP headers, SDP fields, and special methods
- **Success Rate**: 97% (28/29 tests completed successfully)
- **SBC Bypass**: 28% (8/29) channels survive Session Border Controller unchanged
- **C2 Communication Viable**: 8 channels suitable for command and control
- **Maximum Capacity**: 200+ characters per SIP message (X-Headers)
- **Stealth Factor**: High - Most viable channels appear as legitimate SIP traffic

### Encoding Methods Used

- **Base64**: Most common encoding for text payloads
- **ASCII Values**: Numeric encoding for simple commands (OK = 79+75)
- **Binary Encoding**: Header reordering for bit-level communication
- **Custom Formats**: Token@host structures, URI manipulation
- **Steganographic**: Codec reordering, timing manipulation

## Detailed Test Case Information

### High-Viability Channels

**TC-02.14 - X-Headers (Custom Extensions)**
- **Encoding**: Base64 (c2VjcmV0Y29kZTEyMw = "secretcode123")
- **Headers**: X-Covert-Data, X-Token, X-Command
- **Result**: All X-headers passed through SBC unchanged
- **Capacity**: 200+ characters per header, multiple headers supported
- **Use Case**: Primary C2 command transmission

**TC-02.18 - SHAKEN/STIR Identity Header**
- **Encoding**: Base64 embedded in cryptographic signature
- **Result**: Identity header passed through SBC (duplicated)
- **Capacity**: 100+ characters within JWT payload
- **Stealth**: Excellent - appears as legitimate caller authentication
- **Use Case**: Authentication token exchange, high-value command transmission

**TC-02.27 - SDP Media Description Reordering**
- **Encoding**: Binary via codec preference order
- **Example**: PCMA 8 PCMU 0 vs PCMU 0 PCMA 8
- **Result**: Codec ordering preserved through SBC
- **Capacity**: 8-16 bits per message
- **Stealth**: Excellent - appears as normal codec negotiation
- **Use Case**: Status acknowledgments, simple binary commands

**TC-02.29 - S/MIME Signature**
- **Encoding**: Base64 in cryptographic signature field
- **Result**: Signature content passed through unchanged
- **Capacity**: 100+ characters
- **Stealth**: Good - appears as digital signature
- **Use Case**: Secure command transmission, document-based C2

### Session Border Controller Behavior

**Headers Modified by SBC:**
- Via (branch parameter) → Random value generated
- From/To (tag parameters) → Random tags assigned
- Call-ID → New Call-ID generated
- Contact → SBC IP and parameters substituted
- User-Agent → SBC identifier inserted
- Timestamp → SBC processing time added

**Headers Dropped by SBC:**
- Organization, Reply-To, Call-Info, Subject → Removed entirely
- SDP optional fields (k=, i=, a=custom) → Filtered out

**Headers Preserved by SBC:**
- X-Headers → Passed as vendor extensions
- SHAKEN/STIR Identity → Preserved for authentication
- SDP mandatory fields → Required for media negotiation
- S/MIME content → Cryptographic integrity maintained

## Network Topology

**Test Environment:**
```
[Alice/UAC] ──→ [Session Border Controller] ──→ [Bob/UAS]
   SIPp            FreeSWITCH/Kamailio         SIPp
```

**Test Methodology:**
1. Alice (UAC) sends INVITE with covert data
2. SBC processes and potentially modifies headers
3. Bob (UAS) receives final message
4. Packet capture analysis at each hop
5. Covert data extraction and verification

## Implementation Notes

**SIPp XML Scenarios:**
- Each test case includes complete SIP message templates
- Covert data embedded using various encoding schemes
- Scenarios support both manual and automated testing
- Compatible with standard SIP infrastructure

**PCAP Analysis:**
- Captured using tcpdump/tshark at network boundaries
- Analyzed with Wireshark, sngrep, and custom Python scripts
- Headers compared before/after SBC processing
- Covert data extraction verified

## File References for Academic Citation

**Dissertation Chapter Detailed Analysis:**
- X-Headers: `pcap_files/TC-02.14_x_headers.pcap`
- SHAKEN/STIR: `pcap_files/TC-02.18_shaken_stir.pcap`
- SDP Media: `pcap_files/TC-02.27_sdp_media_desc.pcap`
- S/MIME: `pcap_files/TC-02.29_smime_signature.pcap`

**Citation Format:**
```
[Dataset] A42437-ML. (2025). SIP Covert Channel Test Files. 
GitHub Repository. https://github.com/a42437-ml/master_thesis_files
```

## License

This research dataset is released under MIT License for academic and research purposes.

## Contact

For questions about this research:
- **Academic Institution**: [Your University]
- **Research Area**: Network Security, Covert Channels, VoIP Security
- **Thesis**: "SIP-Based Covert Channels for Command and Control Communications"
