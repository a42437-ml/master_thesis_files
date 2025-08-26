
# SIP Covert Channel C2 Server - Proof of Concept

## 🎓 Master's Thesis Research Project

This repository contains a proof-of-concept implementation demonstrating how SIP (Session Initiation Protocol) headers can be exploited as covert channels for Command and Control (C2) communication. This work is part of academic research on network security and covert communication techniques.

## ⚠️ Disclaimer

**This project is for educational and security research purposes only.**

- 🎓 **Academic Research**: Developed as part of master's thesis on network security
- 🔒 **Ethical Use**: Only for authorized security research and defensive analysis
- 🚫 **No Malicious Use**: Do not use for unauthorized access or malicious activities
- 🏫 **Educational Value**: Helps security professionals understand and defend against such techniques

## 📋 Project Overview

### What is a SIP Covert Channel?

Session Initiation Protocol (SIP) is widely used for VoIP communications. This PoC demonstrates how SIP headers can be abused to hide commands and create covert communication channels that bypass traditional security monitoring.

### Attack Scenarios Demonstrated

1. **Command Injection**: Hide system commands in SIP headers
2. **Data Exfiltration**: Extract sensitive information through SIP responses
3. **Persistent Access**: Maintain covert C2 communication
4. **Detection Evasion**: Blend malicious traffic with legitimate SIP communications

## 🏗️ Architecture

```
┌─────────────┐    SIP Messages     ┌─────────────┐    Covert Commands    ┌─────────────┐
│   SIP UAC   │ ──────────────────→ │ FreeSWITCH  │ ──────────────────→  │ C2 Server   │
│  (Client)   │  with Covert Data   │    (SBC)    │  Extracted & Routed  │  (Target)   │
└─────────────┘                     └─────────────┘                      └─────────────┘
```

### Components

- **SIP UAC**: Generates SIP messages with embedded covert commands
- **FreeSWITCH SBC**: Routes SIP traffic (can inspect/modify headers)
- **C2 Server**: Extracts and executes covert commands from SIP headers

## 🔧 Covert Techniques Implemented

### 1. Custom X-Headers
```sip
X-Custom-Data: d2hvYW1p  # base64("whoami")
X-Session-ID: cHdk        # base64("pwd")
```

### 2. User-Agent Manipulation
```sip
User-Agent: FreeSWITCH-1.10.7 (cmd:d2hvYW1p)
```

### 3. Contact Parameter Injection
```sip
Contact: <sip:user@host;data=d2hvYW1p;transport=udp>
```

### 4. Via Branch Parameter
```sip
Via: SIP/2.0/UDP host;branch=z9hG4bKd2hvYW1p
```

## 🚀 Quick Start

### Prerequisites

- Python 3.6+
- Linux environment (tested on Ubuntu/Debian)
- Network access between test systems
- Optional: FreeSWITCH for full SBC testing

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/a42437-ml/master_thesis_files.git
   cd master_thesis_files/c2c_server_poc
   ```

2. **Set up the environment**:
   ```bash
   chmod +x *.py
   pip3 install -r requirements.txt  # if needed
   ```

### Basic Usage

1. **Start the C2 Server**:
   ```bash
   python3 sip_c2_server.py --host 0.0.0.0 --port 5060 --verbose
   ```

2. **Send covert commands** (from another machine):
   ```bash
   python3 simple_sip_client.py -t <C2_SERVER_IP> -c "whoami" --technique header
   ```

## 📊 Real-World Test Results

From actual testing session:
```
📊 SIP Covert C2 Server Statistics:
════════════════════════════════════
🕐 Uptime: 0:00:50.051132
📨 Total SIP messages: 10
🎯 Covert commands detected: 10
✅ Successful executions: 10
🔧 Server: 0.0.0.0:5060
```

**Success Rate**: 100% command detection and execution  
**Detection Method**: X-Custom-Data header analysis  
**Network Setup**: Multi-VM environment with FreeSWITCH SBC

## 📁 Repository Structure

```
c2c_server_poc/
├── README.md                 # This file
├── sip_c2_server.py         # Main C2 server implementation
├── simple_sip_client.py     # Basic test client
├── advanced_client.py       # Multi-technique client
├── sip_monitor.py           # Detection/monitoring tool
├── sip_header_filter.py     # Defensive filtering tool
├── launcher.py              # Master control script
├── requirements.txt         # Python dependencies
├── docs/                    # Detailed documentation
│   ├── SECURITY_ANALYSIS.md # Security implications
│   ├── DETECTION_GUIDE.md   # How to detect these attacks
│   └── SETUP_GUIDE.md       # Detailed setup instructions
├── scenarios/               # Test scenarios
│   ├── sipp_scenarios/      # SIPp test files
│   └── network_configs/     # Network configuration examples
└── logs/                    # Sample log files
    ├── successful_attack.log
    └── detection_alerts.log
```

## 🔒 Security Analysis

### Attack Vectors

1. **Header Injection**: Commands hidden in various SIP headers
2. **Protocol Abuse**: Misuse of legitimate SIP functionality
3. **Traffic Blending**: Covert traffic mixed with legitimate VoIP
4. **Firewall Evasion**: SIP traffic often allowed through firewalls

### Detection Strategies

1. **Deep Packet Inspection**: Analyze SIP header content for anomalies
2. **Pattern Recognition**: Identify base64 or encoded data in headers
3. **Behavioral Analysis**: Monitor for unusual SIP message patterns
4. **Rate Limiting**: Detect excessive SIP traffic from single sources

### Defensive Measures

- **Header Validation**: Strict validation of SIP header content
- **Traffic Filtering**: Block suspicious SIP messages
- **Network Segmentation**: Isolate VoIP infrastructure
- **Continuous Monitoring**: Real-time SIP traffic analysis

## 📈 Research Findings

### Key Insights

1. **Stealth**: Covert channels in SIP are difficult to detect without specific monitoring
2. **Reliability**: 100% success rate in controlled environment
3. **Flexibility**: Multiple header fields can be used for hiding data
4. **Impact**: Potential for persistent, undetected C2 communication

### Contributions

- First documented PoC of SIP header covert channels
- Comprehensive analysis of detection and mitigation strategies
- Open-source tools for security researchers and defenders
- Real-world testing in multi-VM SBC environment

## 🛡️ Defensive Tools Included

### Detection Tools

- **SIP Monitor**: Real-time covert channel detection
- **Header Filter**: Proactive blocking of suspicious traffic
- **Traffic Analyzer**: Historical analysis of SIP communications

### SIEM Integration

- Splunk queries for covert channel detection
- ELK Stack dashboards for SIP traffic analysis
- Snort/Suricata rules for network-based detection

## 🧪 Testing Environment

### Verified Configurations

- **VM Setup**: 3-VM environment (UAC → SBC → UAS/C2)
- **FreeSWITCH**: Version 1.10.7+ as Session Border Controller
- **SIPp**: For generating test SIP traffic
- **Operating Systems**: Ubuntu 20.04+, Debian 10+

### Network Requirements

- UDP port 5060 (standard SIP)
- Network connectivity between test systems
- Firewall rules allowing SIP traffic

## 📚 Academic References

This work builds upon research in:

- Covert channel analysis in network protocols
- VoIP security vulnerabilities
- Session Initiation Protocol specifications (RFC 3261)
- Network steganography techniques

## 👨‍🎓 Author

**Master's Thesis Project**  
Cybersecurity Research  
[University/Institution Name]

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**Academic Use**: Free for educational and research purposes  
**Commercial Use**: Contact author for licensing terms  
**Responsible Disclosure**: Security vulnerabilities should be reported responsibly

## 🤝 Contributing

This is an academic research project. Contributions are welcome in the form of:

- Security analysis improvements
- Additional detection methods
- Documentation enhancements
- Bug fixes and optimizations

Please ensure all contributions maintain the educational focus and ethical use of this research.

## 📞 Contact

For academic collaboration, security research inquiries, or responsible disclosure of vulnerabilities:

- **Issues**: Use GitHub Issues for technical problems
- **Security**: Email for security-related discussions
- **Research**: Contact for academic collaboration opportunities

---

**Remember**: This tool is for authorized security research only. Always obtain proper authorization before testing on networks you do not own.
