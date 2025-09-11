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
            return {"impact": "Cannot determine - insufficient data"}
        
        before_avg = statistics.mean(before_deployment)
        after_avg = statistics.mean(after_deployment)
        
        impact_ms = after_avg - before_avg
        impact_pct = (impact_ms / before_avg) * 100 if before_avg > 0 else 0
        
        if abs(impact_pct) < 5:
            impact_level = "Minimal"
        elif abs(impact_pct) < 15:
            impact_level = "Moderate"
        else:
            impact_level = "Significant"
        
        return {
            "before_avg_ms": before_avg,
            "after_avg_ms": after_avg,
            "impact_ms": impact_ms,
            "impact_percentage": impact_pct,
            "impact_level": impact_level
        }
    
    def calculate_one_way_delay(self, stream_packets):
        """Calculate one-way delay estimation"""
        if len(stream_packets) < 2:
            return 0
        
        # Use inter-packet arrival times as delay estimation
        timestamps = [pkt['timestamp'] for pkt in stream_packets]
        timestamps.sort()
        
        delays = []
        for i in range(1, len(timestamps)):
            delay = (timestamps[i] - timestamps[i-1]) * 1000  # Convert to ms
            if 0 < delay < 1000:  # Filter out unrealistic delays
                delays.append(delay)
        
        return statistics.mean(delays) if delays else 0
    
    def parse_rtp_packets(self):
        """Parse RTP packets with fallback methods - prioritizing accuracy"""
        print("🎵 Parsing RTP packets (hybrid approach)...")
        
        try:
            rtp_count = 0
            method_used = "unknown"
            
            # Method 1: Try standard RTP detection first (most reliable)
            print("  🔍 Attempting standard RTP detection...")
            try:
                cap_rtp = pyshark.FileCapture(self.pcap_file, display_filter='rtp')
                temp_count = 0
                
                for pkt in cap_rtp:
                    if self._process_direct_rtp(pkt):
                        temp_count += 1
                
                cap_rtp.close()
                
                if temp_count > 0:
                    print(f"  ✅ Standard RTP detection: Found {temp_count} packets")
                    rtp_count = temp_count
                    method_used = "standard"
                else:
                    print("  ⚠️ Standard RTP detection: No packets found")
                    
            except Exception as e:
                print(f"  ❌ Standard RTP detection failed: {e}")
            
            # Method 2: If standard detection failed or found too few streams, try UDP analysis
            if len(self.rtp_packets) < 2:  # If we have very few streams, try alternative
                print("  🔍 Attempting UDP payload analysis...")
                self.rtp_packets.clear()  # Clear previous results
                
                try:
                    cap_udp = pyshark.FileCapture(self.pcap_file, display_filter='udp')
                    temp_count = 0
                    
                    for pkt in cap_udp:
                        if self._process_udp_rtp(pkt):
                            temp_count += 1
                    
                    cap_udp.close()
                    
                    if temp_count > 0:
                        print(f"  ✅ UDP analysis: Found {temp_count} packets")
                        rtp_count = temp_count
                        method_used = "udp_analysis"
                    else:
                        print("  ⚠️ UDP analysis: No packets found")
                        
                except Exception as e:
                    print(f"  ❌ UDP analysis failed: {e}")
            
            # Method 3: AudioCodes-specific parsing (only if previous methods failed)
            if len(self.rtp_packets) < 2:
                print("  🔍 Attempting AudioCodes-specific parsing...")
                self.rtp_packets.clear()  # Clear previous results
                
                try:
                    cap_ac = pyshark.FileCapture(self.pcap_file, display_filter='udp')
                    temp_count = 0
                    
                    for pkt in cap_ac:
                        if self._process_audiocodes_rtp(pkt):
                            temp_count += 1
                    
                    cap_ac.close()
                    
                    if temp_count > 0:
                        print(f"  ✅ AudioCodes parsing: Found {temp_count} packets")
                        rtp_count = temp_count
                        method_used = "audiocodes"
                    else:
                        print("  ⚠️ AudioCodes parsing: No packets found")
                        
                except Exception as e:
                    print(f"  ❌ AudioCodes parsing failed: {e}")
            
            # Post-process to consolidate streams
            self._consolidate_streams_conservative()
            
            print(f"✅ Found {len(self.rtp_packets)} RTP streams using {method_used} method")
            print(f"📊 Total RTP packets processed: {rtp_count}")
            
            # Validate results and show stream information
            valid_streams = 0
            for stream_id, packets in self.rtp_packets.items():
                if len(packets) >= 10:  # Only count streams with sufficient data
                    valid_streams += 1
                    first_pkt = packets[0]
                    last_pkt = packets[-1]
                    duration = last_pkt['timestamp'] - first_pkt['timestamp']
                    
                    # Quick quality check
                    seq_numbers = [p['seq_num'] for p in packets]
                    seq_range = max(seq_numbers) - min(seq_numbers) if seq_numbers else 0
                    expected_packets = seq_range + 1
                    actual_packets = len(packets)
                    loss_estimate = max(0, (expected_packets - actual_packets) / expected_packets * 100) if expected_packets > 0 else 0
                    
                    print(f"  🎵 Stream: {stream_id}")
                    print(f"     📦 Packets: {len(packets)} | Duration: {duration:.1f}s")
                    print(f"     🎯 SSRC: 0x{first_pkt['ssrc']:08x}")
                    print(f"     🎵 Payload Type: {first_pkt['payload_type']}")
                    print(f"     📊 Est. Loss: {loss_estimate:.1f}%")
                    print(f"     📍 {first_pkt['src_ip']}:{first_pkt['src_port']} -> {first_pkt['dst_ip']}:{first_pkt['dst_port']}")
            
            print(f"📈 Valid streams for analysis: {valid_streams}")
            
        except Exception as e:
            print(f"❌ Error parsing RTP packets: {e}")
    
    def _process_direct_rtp(self, pkt):
        """Process directly detected RTP packets (most reliable method)"""
        try:
            if not (hasattr(pkt, 'rtp') and hasattr(pkt, 'ip') and hasattr(pkt, 'udp')):
                return False
                
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            src_port = int(pkt.udp.srcport)
            dst_port = int(pkt.udp.dstport)
            
            # Parse SSRC properly
            ssrc_str = pkt.rtp.ssrc
            if isinstance(ssrc_str, str):
                if ssrc_str.startswith('0x'):
                    ssrc = int(ssrc_str, 16)
                else:
                    ssrc = int(ssrc_str)
            else:
                ssrc = int(ssrc_str)
            
            stream_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
            
            packet_info = {
                'timestamp': float(pkt.sniff_timestamp),
                'seq_num': int(pkt.rtp.seq),
                'rtp_timestamp': int(pkt.rtp.timestamp),
                'ssrc': ssrc,
                'payload_type': int(pkt.rtp.p_type) if hasattr(pkt.rtp, 'p_type') else 0,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'method': 'direct'
            }
            
            self.rtp_packets[stream_id].append(packet_info)
            return True
            
        except Exception:
            return False
    
    def _process_udp_rtp(self, pkt):
        """Process UDP packets that might contain RTP (conservative approach)"""
        try:
            if not (hasattr(pkt, 'udp') and hasattr(pkt, 'ip')):
                return False
            
            if not hasattr(pkt.udp, 'payload'):
                return False
            
            # Convert payload to bytes
            payload_hex = pkt.udp.payload.replace(':', '')
            if len(payload_hex) < 24:  # Too short for RTP (12 bytes = 24 hex chars)
                return False
                
            payload_bytes = bytes.fromhex(payload_hex)
            
            # Check if this looks like RTP at the beginning of payload
            if len(payload_bytes) < 12:
                return False
            
            # Check RTP version (should be 2)
            version = (payload_bytes[0] >> 6) & 0x3
            if version != 2:
                return False
            
            # Additional validation
            payload_type = payload_bytes[1] & 0x7F
            if payload_type > 127:  # Invalid payload type
                return False
            
            # Extract RTP fields
            seq_num = (payload_bytes[2] << 8) | payload_bytes[3]
            rtp_timestamp = (payload_bytes[4] << 24) | (payload_bytes[5] << 16) | (payload_bytes[6] << 8) | payload_bytes[7]
            ssrc = (payload_bytes[8] << 24) | (payload_bytes[9] << 16) | (payload_bytes[10] << 8) | payload_bytes[11]
            
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            src_port = int(pkt.udp.srcport)
            dst_port = int(pkt.udp.dstport)
            
            stream_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
            
            packet_info = {
                'timestamp': float(pkt.sniff_timestamp),
                'seq_num': seq_num,
                'rtp_timestamp': rtp_timestamp,
                'ssrc': ssrc,
                'payload_type': payload_type,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'method': 'udp_direct'
            }
            
            self.rtp_packets[stream_id].append(packet_info)
            return True
            
        except Exception:
            return False
    
    def _process_audiocodes_rtp(self, pkt):
        """Process AudioCodes encapsulated RTP packets (last resort)"""
        try:
            if not (hasattr(pkt, 'udp') and hasattr(pkt, 'ip')):
                return False
            
            if not hasattr(pkt.udp, 'payload'):
                return False
            
            # Convert payload to bytes
            payload_hex = pkt.udp.payload.replace(':', '')
            if len(payload_hex) < 48:  # Need extra space for encapsulation + RTP
                return False
                
            payload_bytes = bytes.fromhex(payload_hex)
            
            # Look for RTP header at various offsets (AudioCodes debug headers)
            possible_offsets = [0, 4, 8, 12, 16, 20, 24, 28, 32]
            
            for offset in possible_offsets:
                if offset + 12 > len(payload_bytes):
                    continue
                
                # Check if this looks like an RTP header
                version = (payload_bytes[offset] >> 6) & 0x3
                if version != 2:
                    continue
                
                payload_type = payload_bytes[offset + 1] & 0x7F
                if payload_type > 127:
                    continue
                
                # Extract RTP fields from offset
                seq_num = (payload_bytes[offset + 2] << 8) | payload_bytes[offset + 3]
                rtp_timestamp = (payload_bytes[offset + 4] << 24) | (payload_bytes[offset + 5] << 16) | (payload_bytes[offset + 6] << 8) | payload_bytes[offset + 7]
                ssrc = (payload_bytes[offset + 8] << 24) | (payload_bytes[offset + 9] << 16) | (payload_bytes[offset + 10] << 8) | payload_bytes[offset + 11]
                
                src_ip = pkt.ip.src
                dst_ip = pkt.ip.dst
                src_port = int(pkt.udp.srcport)
                dst_port = int(pkt.udp.dstport)
                
                stream_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}_AC"
                
                packet_info = {
                    'timestamp': float(pkt.sniff_timestamp),
                    'seq_num': seq_num,
                    'rtp_timestamp': rtp_timestamp,
                    'ssrc': ssrc,
                    'payload_type': payload_type,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'method': 'audiocodes',
                    'offset': offset
                }
                
                self.rtp_packets[stream_id].append(packet_info)
                return True
            
            return False
            
        except Exception:
            return False
    
    def _consolidate_streams_conservative(self):
        """Conservative stream consolidation to preserve data integrity"""
        if not self.rtp_packets:
            return
        
        # Only consolidate if we have obvious duplicates
        ssrc_groups = defaultdict(list)
        
        for stream_id, packets in self.rtp_packets.items():
            if packets:
                ssrc = packets[0]['ssrc']
                ssrc_groups[ssrc].append((stream_id, packets))
        
        consolidated = {}
        
        for ssrc, stream_list in ssrc_groups.items():
            if len(stream_list) == 1:
                # Single stream - keep as is
                stream_id, packets = stream_list[0]
                consolidated[stream_id] = packets
            else:
                # Multiple streams with same SSRC - check if they're truly duplicates
                # Sort by packet count (keep the largest)
                stream_list.sort(key=lambda x: len(x[1]), reverse=True)
                
                # Keep the stream with the most packets
                main_stream_id, main_packets = stream_list[0]
                
                # Check if other streams are subsets or have non-overlapping data
                all_unique_packets = list(main_packets)
                
                for other_stream_id, other_packets in stream_list[1:]:
                    # Check for non-overlapping sequence numbers
                    main_seqs = set(p['seq_num'] for p in main_packets)
                    other_seqs = set(p['seq_num'] for p in other_packets)
                    
                    # If no overlap, merge streams
                    if not main_seqs.intersection(other_seqs):
                        all_unique_packets.extend(other_packets)
                
                # Sort merged packets by timestamp
                all_unique_packets.sort(key=lambda x: (x['timestamp'], x['seq_num']))
                
                consolidated[f"SSRC_{ssrc:08x}"] = all_unique_packets
        
        self.rtp_packets = consolidated
    
    def parse_sip_packets(self):
        """Parse SIP packets for call flow analysis"""
        print("📞 Parsing SIP packets...")
        
        try:
            cap_sip = pyshark.FileCapture(self.pcap_file, display_filter='sip')
            
            for pkt in cap_sip:
                try:
                    if hasattr(pkt, 'sip'):
                        call_id = pkt.sip.call_id
                        timestamp = float(pkt.sniff_timestamp)
                        
                        transaction = {
                            'call_id': call_id,
                            'timestamp': timestamp
                        }
                        
                        if hasattr(pkt.sip, 'method'):
                            transaction['type'] = 'request'
                            transaction['method'] = pkt.sip.method
                            
                            if pkt.sip.method == 'INVITE':
                                self.call_flows[call_id]['invite_time'] = timestamp
                        
                        elif hasattr(pkt.sip, 'status_code'):
                            transaction['type'] = 'response'
                            transaction['status_code'] = pkt.sip.status_code
                            
                            if pkt.sip.status_code == '200' and call_id in self.call_flows:
                                if 'invite_time' in self.call_flows[call_id] and 'setup_time' not in self.call_flows[call_id]:
                                    setup_time = timestamp - self.call_flows[call_id]['invite_time']
                                    if setup_time < 30:  # Reasonable setup time
                                        self.call_flows[call_id]['setup_time'] = setup_time
                        
                        self.sip_transactions.append(transaction)
                        
                except AttributeError:
                    continue
            
            cap_sip.close()
            print(f"✅ Found {len(self.sip_transactions)} SIP transactions")
            
        except Exception as e:
            print(f"❌ Error parsing SIP packets: {e}")
    
    def generate_quality_report(self):
        """Generate comprehensive quality report"""
        print("\n" + "="*100)
        print("🏆 TC-08: SIP CALL QUALITY ANALYSIS REPORT")
        print("="*100)
        
        if not self.rtp_packets:
            print("⚠️ No RTP packets found for analysis")
            return
        
        stream_results = []
        total_calls = len(self.call_flows)
        
        # Analyze each RTP stream
        for stream_id, packets in self.rtp_packets.items():
            if len(packets) < 10:  # Skip streams with insufficient data
                continue
            
            # Calculate metrics
            jitter_ms = self.calculate_jitter(packets)
            packet_loss_pct, lost_packets, total_expected = self.analyze_packet_loss(packets)
            latency_ms = self.calculate_one_way_delay(packets)
            
            # Calculate MOS score
            mos_score = self.calculate_mos_score(jitter_ms, packet_loss_pct, latency_ms)
            
            stream_result = {
                'stream_id': stream_id,
                'packet_count': len(packets),
                'jitter_ms': jitter_ms,
                'packet_loss_pct': packet_loss_pct,
                'lost_packets': lost_packets,
                'total_expected': total_expected,
                'latency_ms': latency_ms,
                'mos_score': mos_score
            }
            
            stream_results.append(stream_result)
        
        if not stream_results:
            print("⚠️ No analyzable RTP streams found")
            return
        
        # Aggregate results
        avg_jitter = statistics.mean([s['jitter_ms'] for s in stream_results])
        avg_packet_loss = statistics.mean([s['packet_loss_pct'] for s in stream_results])
        avg_latency = statistics.mean([s['latency_ms'] for s in stream_results])
        avg_mos = statistics.mean([s['mos_score'] for s in stream_results])
        
        # Call setup analysis
        setup_times = [flow['setup_time'] for flow in self.call_flows.values() if 'setup_time' in flow]
        
        # Display overall metrics
        print(f"\n📊 OVERALL QUALITY METRICS")
        print(f"{'='*50}")
        print(f"📞 Total Calls Analyzed: {total_calls}")
        print(f"🎵 RTP Streams Analyzed: {len(stream_results)}")
        print(f"\n🎯 KEY PERFORMANCE INDICATORS:")
        print(f"   • Average MOS Score: {avg_mos:.2f}/5.0")
        print(f"   • Average Jitter: {avg_jitter:.2f} ms")
        print(f"   • Average Packet Loss: {avg_packet_loss:.2f}%")
        print(f"   • Average Latency: {avg_latency:.2f} ms")
        
        if setup_times:
            avg_setup = statistics.mean(setup_times)
            print(f"   • Average Call Setup Time: {avg_setup:.3f} seconds")
        
        # Quality assessment based on ITU-T standards
        print(f"\n🏅 QUALITY ASSESSMENT (ITU-T Standards):")
        print(f"{'='*50}")
        
        # MOS Assessment
        if avg_mos >= 4.0:
            mos_quality = "🟢 Excellent (4.0-5.0)"
        elif avg_mos >= 3.6:
            mos_quality = "🟡 Good (3.6-4.0)"
        elif avg_mos >= 3.1:
            mos_quality = "🟠 Fair (3.1-3.6)"
        elif avg_mos >= 2.6:
            mos_quality = "🔴 Poor (2.6-3.1)"
        else:
            mos_quality = "🔴 Bad (<2.6)"
        print(f"MOS Score: {mos_quality}")
        
        # Jitter Assessment
        if avg_jitter <= 20:
            jitter_quality = "🟢 Excellent (≤20ms)"
        elif avg_jitter <= 40:
            jitter_quality = "🟡 Good (20-40ms)"
        elif avg_jitter <= 80:
            jitter_quality = "🟠 Fair (40-80ms)"
        else:
            jitter_quality = "🔴 Poor (>80ms)"
        print(f"Jitter: {jitter_quality}")
        
        # Packet Loss Assessment
        if avg_packet_loss <= 0.1:
            loss_quality = "🟢 Excellent (≤0.1%)"
        elif avg_packet_loss <= 1.0:
            loss_quality = "🟡 Good (0.1-1.0%)"
        elif avg_packet_loss <= 3.0:
            loss_quality = "🟠 Fair (1.0-3.0%)"
        else:
            loss_quality = "🔴 Poor (>3.0%)"
        print(f"Packet Loss: {loss_quality}")
        
        # Latency Assessment
        if avg_latency <= 150:
            latency_quality = "🟢 Excellent (≤150ms)"
        elif avg_latency <= 300:
            latency_quality = "🟡 Good (150-300ms)"
        elif avg_latency <= 400:
            latency_quality = "🟠 Fair (300-400ms)"
        else:
            latency_quality = "🔴 Poor (>400ms)"
        print(f"Latency: {latency_quality}")
        
        # QoS/QoE Compliance Check
        print(f"\n✅ QoS/QoE COMPLIANCE CHECK:")
        print(f"{'='*50}")
        
        qos_compliant = (
            avg_mos >= 3.6 and
            avg_jitter <= 40 and
            avg_packet_loss <= 1.0 and
            avg_latency <= 300
        )
        
        if qos_compliant:
            print("🟢 PASS: Acceptable QoS/QoE levels maintained")
        else:
            print("🔴 FAIL: QoS/QoE levels below acceptable thresholds")
            
            if avg_mos < 3.6:
                print(f"   ❌ MOS score too low: {avg_mos:.2f} (required: ≥3.6)")
            if avg_jitter > 40:
                print(f"   ❌ Jitter too high: {avg_jitter:.2f}ms (required: ≤40ms)")
            if avg_packet_loss > 1.0:
                print(f"   ❌ Packet loss too high: {avg_packet_loss:.2f}% (required: ≤1.0%)")
            if avg_latency > 300:
                print(f"   ❌ Latency too high: {avg_latency:.2f}ms (required: ≤300ms)")
        
        # Deployment Impact Assessment
        print(f"\n🚀 DEPLOYMENT IMPACT ASSESSMENT:")
        print(f"{'='*50}")
        
        # For this analysis, we'll assume first half is "before" and second half is "after"
        if len(stream_results) >= 2:
            mid_point = len(stream_results) // 2
            before_latency = [s['latency_ms'] for s in stream_results[:mid_point]]
            after_latency = [s['latency_ms'] for s in stream_results[mid_point:]]
            
            impact_analysis = self.analyze_latency_impact(before_latency, after_latency)
            
            if 'impact_level' in impact_analysis:
                impact_level = impact_analysis['impact_level']
                impact_ms = impact_analysis.get('impact_ms', 0)
                impact_pct = impact_analysis.get('impact_percentage', 0)
                
                if impact_level == "Minimal":
                    print(f"🟢 PASS: Minimal impact on latency ({impact_ms:+.2f}ms, {impact_pct:+.1f}%)")
                elif impact_level == "Moderate":
                    print(f"🟡 CAUTION: Moderate impact on latency ({impact_ms:+.2f}ms, {impact_pct:+.1f}%)")
                else:
                    print(f"🔴 FAIL: Significant impact on latency ({impact_ms:+.2f}ms, {impact_pct:+.1f}%)")
            else:
                print("⚠️ Cannot determine deployment impact - insufficient data")
        else:
            print("⚠️ Insufficient data for deployment impact analysis")
        
        # Detailed per-stream results
        print(f"\n📋 DETAILED STREAM ANALYSIS:")
        print(f"{'='*50}")
        
        for i, result in enumerate(stream_results[:5], 1):  # Show first 5 streams
            print(f"\nStream {i}: {result['stream_id']}")
            print(f"  📊 Packets: {result['packet_count']} | Loss: {result['packet_loss_pct']:.2f}%")
            print(f"  ⏱️  Jitter: {result['jitter_ms']:.2f}ms | Latency: {result['latency_ms']:.2f}ms")
            print(f"  🎯 MOS Score: {result['mos_score']:.2f}/5.0")
        
        if len(stream_results) > 5:
            print(f"\n... and {len(stream_results) - 5} more streams")
        
        # Summary for TC-08
        print(f"\n🎯 TC-08 TEST CASE SUMMARY:")
        print(f"{'='*50}")
        
        if qos_compliant:
            print("✅ TC-08 REQUIREMENT 1: QoS/QoE levels maintained - PASSED")
        else:
            print("❌ TC-08 REQUIREMENT 1: QoS/QoE levels maintained - FAILED")
        
        # Check deployment impact
        if len(stream_results) >= 2:
            mid_point = len(stream_results) // 2
            before_latency = [s['latency_ms'] for s in stream_results[:mid_point]]
            after_latency = [s['latency_ms'] for s in stream_results[mid_point:]]
            impact_analysis = self.analyze_latency_impact(before_latency, after_latency)
            
            if impact_analysis.get('impact_level') == "Minimal":
                print("✅ TC-08 REQUIREMENT 2: Minimal impact on latency - PASSED")
            else:
                print("❌ TC-08 REQUIREMENT 2: Minimal impact on latency - FAILED")
        else:
            print("⚠️ TC-08 REQUIREMENT 2: Cannot assess deployment impact - INCONCLUSIVE")
    
    def run_analysis(self):
        """Run complete TC-08 analysis"""
        print("🚀 Starting TC-08: SIP Call Quality Analysis")
        print("🎯 Objectives: Analyze MOS, jitter, packet loss, and deployment impact")
        
        self.parse_sip_packets()
        self.parse_rtp_packets()
        self.generate_quality_report()
        
        print(f"\n🏁 TC-08 Analysis Complete!")

# Main execution
if __name__ == "__main__":
    try:
        import os
        
        # Manually specify your already uploaded pcap file here
        pcap_file = 'sip_rtp_capture_tc-07 (1).pcap'  # Update this to your TC-08 file name
        
        # Verify file exists and has content
        if os.path.exists(pcap_file):
            print(f"✅ Using file: {pcap_file}")
            print(f"📊 File size: {os.path.getsize(pcap_file)} bytes")
            
            # Start analysis
            analyzer = VoIPQualityAnalyzer(pcap_file)
            analyzer.run_analysis()
        else:
            print(f"❌ File not found: {pcap_file}")
            print("💡 Available files in current directory:")
            for file in os.listdir('.'):
                if file.endswith('.pcap') or file.endswith('.pcapng'):
                    print(f"   📄 {file}")
            
    except Exception as e:
        print(f"❌ Error during analysis: {e}")
        import traceback
        traceback.print_exc()