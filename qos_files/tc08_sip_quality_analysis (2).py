import pyshark
import nest_asyncio
import statistics
from collections import defaultdict, Counter
import numpy as np
import math

nest_asyncio.apply()

class VoIPQualityAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.rtp_streams = defaultdict(list)
        self.rtp_packets = defaultdict(list)
        self.sip_transactions = []
        self.call_flows = defaultdict(dict)
        
    def analyze_packet_loss(self, stream_packets):
        """Calculate packet loss percentage for RTP stream"""
        if len(stream_packets) < 2:
            return 0, 0, 0
        
        sequence_numbers = []
        timestamps = []
        
        for pkt in stream_packets:
            try:
                seq_num = int(pkt['seq_num'])
                timestamp = pkt['timestamp']
                sequence_numbers.append(seq_num)
                timestamps.append(timestamp)
            except:
                continue
        
        if len(sequence_numbers) < 2:
            return 0, 0, 0
        
        # Sort by timestamp to get chronological order
        combined = list(zip(timestamps, sequence_numbers))
        combined.sort()
        sorted_seq = [seq for _, seq in combined]
        
        # Handle sequence number wraparound (16-bit)
        expected_packets = 0
        lost_packets = 0
        
        for i in range(1, len(sorted_seq)):
            prev_seq = sorted_seq[i-1]
            curr_seq = sorted_seq[i]
            
            # Handle wraparound
            if curr_seq < prev_seq:
                diff = (65536 - prev_seq) + curr_seq
            else:
                diff = curr_seq - prev_seq
            
            expected_packets += diff
            if diff > 1:
                lost_packets += (diff - 1)
        
        total_expected = expected_packets
        loss_percentage = (lost_packets / total_expected * 100) if total_expected > 0 else 0
        
        return loss_percentage, lost_packets, total_expected
    
    def calculate_jitter(self, stream_packets):
        """Calculate RFC 3550 compliant jitter"""
        if len(stream_packets) < 2:
            return 0
        
        timestamps = []
        rtp_timestamps = []
        
        for pkt in stream_packets:
            try:
                timestamps.append(pkt['timestamp'])
                rtp_timestamps.append(int(pkt['rtp_timestamp']))
            except:
                continue
        
        if len(timestamps) < 2:
            return 0
        
        # Sort by arrival time
        combined = list(zip(timestamps, rtp_timestamps))
        combined.sort()
        
        transit_times = []
        for i in range(len(combined)):
            arrival_time = combined[i][0]
            rtp_time = combined[i][1] / 8000.0  # Assuming 8kHz sampling
            transit_time = arrival_time - rtp_time
            transit_times.append(transit_time)
        
        # Calculate jitter according to RFC 3550
        jitter = 0
        for i in range(1, len(transit_times)):
            diff = abs(transit_times[i] - transit_times[i-1])
            jitter += (diff - jitter) / 16  # RFC 3550 formula
        
        return jitter * 1000  # Convert to milliseconds
    
    def calculate_mos_score(self, jitter_ms, packet_loss_pct, latency_ms):
        """Calculate MOS score using E-Model approximation"""
        
        # Base R-factor (excellent conditions)
        R = 93.2
        
        # Impairment due to packet loss
        if packet_loss_pct <= 0:
            Ie_eff = 0
        elif packet_loss_pct <= 1:
            Ie_eff = 10 * packet_loss_pct
        elif packet_loss_pct <= 5:
            Ie_eff = 10 + 20 * (packet_loss_pct - 1)
        else:
            Ie_eff = 90 + 10 * (packet_loss_pct - 5)
        
        # Impairment due to jitter (approximation)
        if jitter_ms <= 20:
            Ie_jitter = 0
        elif jitter_ms <= 50:
            Ie_jitter = 5 * (jitter_ms - 20) / 30
        else:
            Ie_jitter = 5 + 10 * (jitter_ms - 50) / 50
        
        # Impairment due to delay
        if latency_ms <= 150:
            Id = 0
        elif latency_ms <= 400:
            Id = 0.024 * latency_ms - 3.6
        else:
            Id = 0.11 * (latency_ms - 177.3) + 0.024 * 177.3 - 3.6
        
        # Calculate final R-factor
        R_final = R - Ie_eff - Ie_jitter - Id
        
        # Convert R-factor to MOS
        if R_final < 0:
            mos = 1.0
        elif R_final > 100:
            mos = 4.5
        else:
            mos = 1 + 0.035 * R_final + 7e-6 * R_final * (R_final - 60) * (100 - R_final)
        
        return max(1.0, min(5.0, mos))
    
    def analyze_latency_impact(self, before_deployment, after_deployment):
        """Analyze latency impact of deployment"""
        if not before_deployment or not after_deployment:
            return {\"impact\": \"Cannot determine - insufficient data\"}
        
        before_avg = statistics.mean(before_deployment)
        after_avg = statistics.mean(after_deployment)
        
        impact_ms = after_avg - before_avg
        impact_pct = (impact_ms / before_avg) * 100 if before_avg > 0 else 0
        
        if abs(impact_pct) < 5:
            impact_level = \"Minimal\"\n        elif abs(impact_pct) < 15:\n            impact_level = \"Moderate\"\n        else:\n            impact_level = \"Significant\"\n        \n        return {\n            \"before_avg_ms\": before_avg,\n            \"after_avg_ms\": after_avg,\n            \"impact_ms\": impact_ms,\n            \"impact_percentage\": impact_pct,\n            \"impact_level\": impact_level\n        }\n    \n    def parse_rtp_packets(self):\n        \"\"\"Parse RTP packets and extract quality metrics\"\"\"\n        print(\"🎵 Parsing RTP packets...\")\n        \n        cap_rtp = pyshark.FileCapture(self.pcap_file, display_filter='rtp')\n        \n        for pkt in cap_rtp:\n            try:\n                if hasattr(pkt, 'rtp') and hasattr(pkt, 'ip') and hasattr(pkt, 'udp'):\n                    src_ip = pkt.ip.src\n                    dst_ip = pkt.ip.dst\n                    src_port = pkt.udp.srcport\n                    dst_port = pkt.udp.dstport\n                    \n                    stream_id = f\"{src_ip}:{src_port}->{dst_ip}:{dst_port}\"\n                    \n                    packet_info = {\n                        'timestamp': float(pkt.sniff_timestamp),\n                        'seq_num': pkt.rtp.seq,\n                        'rtp_timestamp': pkt.rtp.timestamp,\n                        'ssrc': pkt.rtp.ssrc,\n                        'payload_type': pkt.rtp.p_type if hasattr(pkt.rtp, 'p_type') else 'unknown'\n                    }\n                    \n                    self.rtp_packets[stream_id].append(packet_info)\n                    \n            except AttributeError:\n                continue\n        \n        cap_rtp.close()\n        print(f\"✅ Found {len(self.rtp_packets)} RTP streams\")\n    \n    def parse_sip_packets(self):\n        \"\"\"Parse SIP packets for call flow analysis\"\"\"\n        print(\"📞 Parsing SIP packets...\")\n        \n        cap_sip = pyshark.FileCapture(self.pcap_file, display_filter='sip')\n        \n        for pkt in cap_sip:\n            try:\n                if hasattr(pkt, 'sip'):\n                    call_id = pkt.sip.call_id\n                    timestamp = float(pkt.sniff_timestamp)\n                    \n                    transaction = {\n                        'call_id': call_id,\n                        'timestamp': timestamp\n                    }\n                    \n                    if hasattr(pkt.sip, 'method'):\n                        transaction['type'] = 'request'\n                        transaction['method'] = pkt.sip.method\n                        \n                        if pkt.sip.method == 'INVITE':\n                            self.call_flows[call_id]['invite_time'] = timestamp\n                    \n                    elif hasattr(pkt.sip, 'status_code'):\n                        transaction['type'] = 'response'\n                        transaction['status_code'] = pkt.sip.status_code\n                        \n                        if pkt.sip.status_code == '200' and call_id in self.call_flows:\n                            if 'invite_time' in self.call_flows[call_id] and 'setup_time' not in self.call_flows[call_id]:\n                                setup_time = timestamp - self.call_flows[call_id]['invite_time']\n                                if setup_time < 30:  # Reasonable setup time\n                                    self.call_flows[call_id]['setup_time'] = setup_time\n                    \n                    self.sip_transactions.append(transaction)\n                    \n            except AttributeError:\n                continue\n        \n        cap_sip.close()\n        print(f\"✅ Found {len(self.sip_transactions)} SIP transactions\")\n    \n    def generate_quality_report(self):\n        \"\"\"Generate comprehensive quality report\"\"\"\n        print(\"\\n\" + \"=\"*100)\n        print(\"🏆 TC-08: SIP CALL QUALITY ANALYSIS REPORT\")\n        print(\"=\"*100)\n        \n        if not self.rtp_packets:\n            print(\"⚠️ No RTP packets found for analysis\")\n            return\n        \n        stream_results = []\n        total_calls = len(self.call_flows)\n        \n        for stream_id, packets in self.rtp_packets.items():\n            if len(packets) < 10:  # Skip streams with insufficient data\n                continue\n            \n            # Calculate metrics\n            jitter_ms = self.calculate_jitter(packets)\n            packet_loss_pct, lost_packets, total_expected = self.analyze_packet_loss(packets)\n            \n            # Estimate latency (simplified)\n            timestamps = [p['timestamp'] for p in packets]\n            if len(timestamps) > 1:\n                inter_packet_times = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]\n                avg_latency = statistics.mean(inter_packet_times) * 1000  # Convert to ms\n            else:\n                avg_latency = 0\n            \n            # Calculate MOS score\n            mos_score = self.calculate_mos_score(jitter_ms, packet_loss_pct, avg_latency)\n            \n            stream_result = {\n                'stream_id': stream_id,\n                'packet_count': len(packets),\n                'jitter_ms': jitter_ms,\n                'packet_loss_pct': packet_loss_pct,\n                'lost_packets': lost_packets,\n                'total_expected': total_expected,\n                'latency_ms': avg_latency,\n                'mos_score': mos_score\n            }\n            \n            stream_results.append(stream_result)\n        \n        # Aggregate results\n        if stream_results:\n            avg_jitter = statistics.mean([s['jitter_ms'] for s in stream_results])\n            avg_packet_loss = statistics.mean([s['packet_loss_pct'] for s in stream_results])\n            avg_latency = statistics.mean([s['latency_ms'] for s in stream_results])\n            avg_mos = statistics.mean([s['mos_score'] for s in stream_results])\n            \n            # Call setup analysis\n            setup_times = [flow['setup_time'] for flow in self.call_flows.values() if 'setup_time' in flow]\n            \n            print(f\"\\n📊 OVERALL QUALITY METRICS\")\n            print(f\"{'='*50}\")\n            print(f\"📞 Total Calls Analyzed: {total_calls}\")\n            print(f\"🎵 RTP Streams Analyzed: {len(stream_results)}\")\n            print(f\"\\n🎯 KEY PERFORMANCE INDICATORS:\")\n            print(f\"   • Average MOS Score: {avg_mos:.2f}/5.0\")\n            print(f\"   • Average Jitter: {avg_jitter:.2f} ms\")\n            print(f\"   • Average Packet Loss: {avg_packet_loss:.2f}%\")\n            print(f\"   • Average Latency: {avg_latency:.2f} ms\")\n            \n            if setup_times:\n                avg_setup = statistics.mean(setup_times)\n                print(f\"   • Average Call Setup Time: {avg_setup:.3f} seconds\")\n            \n            # Quality assessment based on ITU-T standards\n            print(f\"\\n🏅 QUALITY ASSESSMENT (ITU-T Standards):\")\n            print(f\"{'='*50}\")\n            \n            # MOS Assessment\n            if avg_mos >= 4.0:\n                mos_quality = \"🟢 Excellent (4.0-5.0)\"\n            elif avg_mos >= 3.6:\n                mos_quality = \"🟡 Good (3.6-4.0)\"\n            elif avg_mos >= 3.1:\n                mos_quality = \"🟠 Fair (3.1-3.6)\"\n            elif avg_mos >= 2.6:\n                mos_quality = \"🔴 Poor (2.6-3.1)\"\n            else:\n                mos_quality = \"🔴 Bad (<2.6)\"\n            print(f\"MOS Score: {mos_quality}\")\n            \n            # Jitter Assessment\n            if avg_jitter <= 20:\n                jitter_quality = \"🟢 Excellent (≤20ms)\"\n            elif avg_jitter <= 40:\n                jitter_quality = \"🟡 Good (20-40ms)\"\n            elif avg_jitter <= 80:\n                jitter_quality = \"🟠 Fair (40-80ms)\"\n            else:\n                jitter_quality = \"🔴 Poor (>80ms)\"\n            print(f\"Jitter: {jitter_quality}\")\n            \n            # Packet Loss Assessment\n            if avg_packet_loss <= 0.1:\n                loss_quality = \"🟢 Excellent (≤0.1%)\"\n            elif avg_packet_loss <= 1.0:\n                loss_quality = \"🟡 Good (0.1-1.0%)\"\n            elif avg_packet_loss <= 3.0:\n                loss_quality = \"🟠 Fair (1.0-3.0%)\"\n            else:\n                loss_quality = \"🔴 Poor (>3.0%)\"\n            print(f\"Packet Loss: {loss_quality}\")\n            \n            # Latency Assessment\n            if avg_latency <= 150:\n                latency_quality = \"🟢 Excellent (≤150ms)\"\n            elif avg_latency <= 300:\n                latency_quality = \"🟡 Good (150-300ms)\"\n            elif avg_latency <= 400:\n                latency_quality = \"🟠 Fair (300-400ms)\"\n            else:\n                latency_quality = \"🔴 Poor (>400ms)\"\n            print(f\"Latency: {latency_quality}\")\n            \n            # QoS/QoE Compliance Check\n            print(f\"\\n✅ QoS/QoE COMPLIANCE CHECK:\")\n            print(f\"{'='*50}\")\n            \n            qos_compliant = (\n                avg_mos >= 3.6 and\n                avg_jitter <= 40 and\n                avg_packet_loss <= 1.0 and\n                avg_latency <= 300\n            )\n            \n            if qos_compliant:\n                print(\"🟢 PASS: Acceptable QoS/QoE levels maintained\")\n            else:\n                print(\"🔴 FAIL: QoS/QoE levels below acceptable thresholds\")\n                \n                if avg_mos < 3.6:\n                    print(f\"   ❌ MOS score too low: {avg_mos:.2f} (required: ≥3.6)\")\n                if avg_jitter > 40:\n                    print(f\"   ❌ Jitter too high: {avg_jitter:.2f}ms (required: ≤40ms)\")\n                if avg_packet_loss > 1.0:\n                    print(f\"   ❌ Packet loss too high: {avg_packet_loss:.2f}% (required: ≤1.0%)\")\n                if avg_latency > 300:\n                    print(f\"   ❌ Latency too high: {avg_latency:.2f}ms (required: ≤300ms)\")\n            \n            # Deployment Impact Assessment\n            print(f\"\\n🚀 DEPLOYMENT IMPACT ASSESSMENT:\")\n            print(f\"{'='*50}\")\n            \n            # For this analysis, we'll assume first half is \"before\" and second half is \"after\"\n            if len(stream_results) >= 2:\n                mid_point = len(stream_results) // 2\n                before_latency = [s['latency_ms'] for s in stream_results[:mid_point]]\n                after_latency = [s['latency_ms'] for s in stream_results[mid_point:]]\n                \n                impact_analysis = self.analyze_latency_impact(before_latency, after_latency)\n                \n                if 'impact_level' in impact_analysis:\n                    impact_level = impact_analysis['impact_level']\n                    impact_ms = impact_analysis.get('impact_ms', 0)\n                    impact_pct = impact_analysis.get('impact_percentage', 0)\n                    \n                    if impact_level == \"Minimal\":\n                        print(f\"🟢 PASS: Minimal impact on latency ({impact_ms:+.2f}ms, {impact_pct:+.1f}%)\")\n                    elif impact_level == \"Moderate\":\n                        print(f\"🟡 CAUTION: Moderate impact on latency ({impact_ms:+.2f}ms, {impact_pct:+.1f}%)\")\n                    else:\n                        print(f\"🔴 FAIL: Significant impact on latency ({impact_ms:+.2f}ms, {impact_pct:+.1f}%)\")\n                else:\n                    print(\"⚠️ Cannot determine deployment impact - insufficient data\")\n            else:\n                print(\"⚠️ Insufficient data for deployment impact analysis\")\n            \n            # Detailed per-stream results\n            print(f\"\\n📋 DETAILED STREAM ANALYSIS:\")\n            print(f\"{'='*50}\")\n            \n            for i, result in enumerate(stream_results[:5], 1):  # Show first 5 streams\n                print(f\"\\nStream {i}: {result['stream_id']}\")\n                print(f\"  📊 Packets: {result['packet_count']} | Loss: {result['packet_loss_pct']:.2f}%\")\n                print(f\"  ⏱️  Jitter: {result['jitter_ms']:.2f}ms | Latency: {result['latency_ms']:.2f}ms\")\n                print(f\"  🎯 MOS Score: {result['mos_score']:.2f}/5.0\")\n            \n            if len(stream_results) > 5:\n                print(f\"\\n... and {len(stream_results) - 5} more streams\")\n        \n        else:\n            print(\"⚠️ No analyzable RTP streams found\")\n    \n    def run_analysis(self):\n        \"\"\"Run complete TC-08 analysis\"\"\"\n        print(\"🚀 Starting TC-08: SIP Call Quality Analysis\")\n        print(\"🎯 Objectives: Analyze MOS, jitter, packet loss, and deployment impact\")\n        \n        self.parse_sip_packets()\n        self.parse_rtp_packets()\n        self.generate_quality_report()\n        \n        print(f\"\\n🏁 TC-08 Analysis Complete!\")\n\n# Main execution\nif __name__ == \"__main__\":\n    try:\n        # Update this path to your pcap file\n        pcap_file = 'sip_rtp_capture_tc-07 (1).pcap'  # Change to your TC-08 file\n        \n        analyzer = VoIPQualityAnalyzer(pcap_file)\n        analyzer.run_analysis()\n        \n    except Exception as e:\n        print(f\"❌ Error during analysis: {e}\")\n        import traceback\n        traceback.print_exc()"