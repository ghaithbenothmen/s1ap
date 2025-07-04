#!/usr/bin/env python3
"""
S1AP PCAP Analyzer for your specific PCAP file
Analyzes S1CP.pcap and displays all S1AP messages with detailed IE information
"""

import sys
import os
import json
from pathlib import Path
from datetime import datetime

# Add src to Python path
project_root = Path(__file__).parent
src_path = project_root / "src"
sys.path.insert(0, str(src_path))

def analyze_s1cp_pcap():
    """Analyze your S1CP.pcap file"""
    
    print("🔍 S1AP PCAP Analyzer - Clean Version")
    print("=" * 60)
    
    # Look for PCAP file
    pcap_file = "s1CP.pcap"
    if not Path(pcap_file).exists():
        pcap_file = "../s1ap_decoder/s1CP.pcap"  # Try old location
        if not Path(pcap_file).exists():
            print("❌ s1CP.pcap file not found")
            print("Please copy your PCAP file to the current directory")
            return False
    
    try:
        from s1ap_decoder.core import S1APDecoder
        
        print(f"📂 Analyzing: {pcap_file}")
        print(f"🕐 Start time: {datetime.now().strftime('%H:%M:%S')}")
        
        # Create decoder
        decoder = S1APDecoder()
        
        # Parse PCAP file
        messages = decoder.parse_pcap_file(pcap_file, max_packets=10)  # First 10 packets
        
        print(f"\n📊 Analysis Results:")
        print(f"   S1AP messages found: {len(messages)}")
        
        if not messages:
            print("   No S1AP messages found")
            return False
        
        # Display each message with detailed IE information
        for i, msg in enumerate(messages, 1):
            print(f"\n" + "="*60)
            print(f"📦 MESSAGE #{i} - Packet {msg.packet_number}")
            print(f"   Timestamp: {datetime.fromtimestamp(msg.timestamp).strftime('%H:%M:%S.%f')[:-3]}")
            print(f"   Procedure: {msg.procedure_name} ({msg.procedure_code})")
            print(f"   Message Type: {msg.message_type}")
            print(f"   Criticality: {msg.criticality}")
            print(f"   Raw data length: {len(msg.raw_data)} bytes")
            print(f"   IEs found: {len(msg.ies)}")
            
            if msg.parsing_errors:
                print(f"   ⚠️  Parsing errors: {len(msg.parsing_errors)}")
                for error in msg.parsing_errors:
                    print(f"      • {error}")
            
            # Display all IEs with full details
            if msg.ies:
                print(f"\n   🏷️  INFORMATION ELEMENTS:")
                for j, ie in enumerate(msg.ies, 1):
                    print(f"      IE #{j}: {ie['name']} (ID: {ie['id']})")
                    print(f"         ├─ Criticality: {ie['criticality']}")
                    print(f"         ├─ Length: {ie['length']} bytes")
                    print(f"         ├─ Value (hex): {ie['value_hex']}")
                    
                    # Show analyzed content
                    if ie.get('analyzed_content'):
                        print(f"         ├─ Analyzed Content:")
                        for key, value in ie['analyzed_content'].items():
                            if key != 'raw_value':
                                print(f"         │  └─ {key}: {value}")
                    
                    # Show debug info
                    if ie.get('debug_info'):
                        debug = ie['debug_info']
                        print(f"         └─ Debug: Position={debug.get('position', 'N/A')}, "
                              f"Value start={debug.get('value_start', 'N/A')}")
            else:
                print(f"   📭 No IEs found")
        
        # Final statistics
        stats = decoder.get_statistics()
        print(f"\n" + "="*60)
        print(f"📈 FINAL STATISTICS:")
        print(f"   Total packets processed: {stats['total_packets']}")
        print(f"   SCTP packets found: {stats['sctp_packets']}")
        print(f"   S1AP messages decoded: {stats['s1ap_messages']}")
        
        if stats['procedures']:
            print(f"   Procedures distribution:")
            for proc, count in sorted(stats['procedures'].items(), key=lambda x: x[1], reverse=True):
                print(f"      • {proc}: {count} message(s)")
        
        if stats['ies_found']:
            print(f"   Information Elements found:")
            for ie_name, count in sorted(stats['ies_found'].items(), key=lambda x: x[1], reverse=True):
                print(f"      • {ie_name}: {count} occurrence(s)")
        
        if stats['errors']:
            print(f"   ⚠️  Errors encountered: {len(stats['errors'])}")
            for error in stats['errors']:
                print(f"      • {error}")
        
        # Save results to JSON
        output_file = f"s1ap_analysis_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        save_detailed_results(messages, stats, output_file)
        print(f"\n💾 Detailed results saved to: {output_file}")
        
        print(f"\n✅ Analysis completed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Analysis failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def save_detailed_results(messages, stats, filename):
    """Save comprehensive analysis results"""
    
    results = {
        "analysis_info": {
            "analyzer_version": "S1AP Decoder v1.0",
            "analysis_timestamp": datetime.now().isoformat(),
            "total_messages": len(messages),
            "clean_decoder": True
        },
        "statistics": stats,
        "messages": []
    }
    
    for msg in messages:
        msg_data = {
            "packet_number": msg.packet_number,
            "timestamp": msg.timestamp,
            "human_time": datetime.fromtimestamp(msg.timestamp).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            "s1ap_info": {
                "message_type": msg.message_type,
                "procedure_code": msg.procedure_code,
                "procedure_name": msg.procedure_name,
                "criticality": msg.criticality,
                "raw_data_length": len(msg.raw_data),
                "raw_hex": msg.raw_data.hex()
            },
            "ies": msg.ies,
            "ie_count": len(msg.ies),
            "parsing_errors": msg.parsing_errors,
            "has_errors": len(msg.parsing_errors) > 0
        }
        results["messages"].append(msg_data)
    
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

if __name__ == "__main__":
    success = analyze_s1cp_pcap()
    sys.exit(0 if success else 1)
