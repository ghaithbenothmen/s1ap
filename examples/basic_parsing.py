#!/usr/bin/env python3
"""
Basic S1AP Decoder Example
Demonstrates how to use the S1AP decoder to parse PCAP files
"""

import sys
import json
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from s1ap_decoder import S1APDecoder

def main():
    """Main function demonstrating basic usage"""
    
    # Check command line arguments
    if len(sys.argv) != 2:
        print("Usage: python basic_parsing.py <pcap_file>")
        print("Example: python basic_parsing.py capture.pcap")
        return
    
    pcap_file = sys.argv[1]
    
    # Check if file exists
    if not Path(pcap_file).exists():
        print(f"Error: File '{pcap_file}' not found")
        return
    
    print(f"🔍 S1AP Decoder - Parsing: {pcap_file}")
    print("=" * 60)
    
    # Create decoder instance
    decoder = S1APDecoder()
    
    try:
        # Parse PCAP file (limit to first 10 packets for demo)
        messages = decoder.parse_pcap_file(pcap_file, max_packets=10)
        
        # Display results
        print(f"📊 Parsing completed!")
        print(f"   S1AP messages found: {len(messages)}")
        
        if not messages:
            print("   No S1AP messages found in the file")
            return
        
        # Display each message
        for i, msg in enumerate(messages, 1):
            print(f"\n📦 Message #{i} (Packet {msg.packet_number})")
            print(f"   Procedure: {msg.procedure_name}")
            print(f"   Type: {msg.message_type}")
            print(f"   IEs found: {msg.ie_count}")
            
            if msg.has_errors:
                print(f"   ⚠️  Parsing errors: {len(msg.parsing_errors)}")
                for error in msg.parsing_errors[:2]:  # Show first 2 errors
                    print(f"      • {error}")
            
            # Display IEs
            if msg.ies:
                print(f"   Information Elements:")
                for ie in msg.ies[:5]:  # Show first 5 IEs
                    print(f"      • {ie['name']} (ID: {ie['id']}, Length: {ie['length']})")
                    
                    # Show analyzed content if available
                    if ie.get('analyzed_content'):
                        for key, value in ie['analyzed_content'].items():
                            if key != 'raw_value':
                                print(f"        └─ {key}: {value}")
                
                if len(msg.ies) > 5:
                    print(f"      ... and {len(msg.ies) - 5} more IEs")
        
        # Display statistics
        stats = decoder.get_statistics()
        print(f"\n📈 Statistics:")
        print(f"   Total packets processed: {stats['total_packets']}")
        print(f"   SCTP packets found: {stats['sctp_packets']}")
        print(f"   S1AP messages decoded: {stats['s1ap_messages']}")
        
        if stats['procedures']:
            print(f"   Procedures found:")
            for proc, count in stats['procedures'].items():
                print(f"      • {proc}: {count}")
        
        if stats['ies_found']:
            print(f"   Most common IEs:")
            sorted_ies = sorted(stats['ies_found'].items(), key=lambda x: x[1], reverse=True)
            for ie_name, count in sorted_ies[:5]:
                print(f"      • {ie_name}: {count}")
        
        if stats['errors']:
            print(f"   ⚠️  Errors encountered: {len(stats['errors'])}")
            for error in stats['errors'][:3]:
                print(f"      • {error}")
        
        # Optionally save results to JSON
        output_file = f"{Path(pcap_file).stem}_s1ap_results.json"
        save_results(messages, stats, output_file)
        print(f"\n💾 Results saved to: {output_file}")
        
    except Exception as e:
        print(f"❌ Error processing file: {e}")
        import traceback
        traceback.print_exc()

def save_results(messages, stats, filename):
    """Save parsing results to JSON file"""
    
    # Convert messages to serializable format
    results_data = {
        "analysis_info": {
            "total_messages": len(messages),
            "analysis_timestamp": "2025-07-04T00:00:00",
            "decoder_version": "1.0.0"
        },
        "statistics": stats,
        "messages": []
    }
    
    for msg in messages:
        msg_data = {
            "packet_number": msg.packet_number,
            "timestamp": msg.timestamp,
            "message_type": msg.message_type,
            "procedure_code": msg.procedure_code,
            "procedure_name": msg.procedure_name,
            "criticality": msg.criticality,
            "ie_count": msg.ie_count,
            "ies": msg.ies,
            "parsing_errors": msg.parsing_errors,
            "raw_data_length": len(msg.raw_data)
        }
        results_data["messages"].append(msg_data)
    
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(results_data, f, indent=2, ensure_ascii=False)

if __name__ == "__main__":
    main()
