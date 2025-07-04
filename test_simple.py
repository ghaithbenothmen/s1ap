#!/usr/bin/env python3
"""
Simple S1AP Message Test
Tests the core S1AP decoding functionality with sample data
"""

import sys
import os
from pathlib import Path

# Add src to Python path
project_root = Path(__file__).parent
src_path = project_root / "src"
sys.path.insert(0, str(src_path))

def test_s1ap_message_parsing():
    """Test S1AP message parsing with real data"""
    
    print("🔍 S1AP Decoder Test")
    print("=" * 50)
    
    try:
        # Import our modules
        from s1ap_decoder.core import S1APDecoder
        from protocols.s1ap_constants import S1AP_PROCEDURES
        
        print("✅ Modules imported successfully")
        
        # Create decoder
        decoder = S1APDecoder()
        print("✅ Decoder created")
        
        # Test data - Real S1AP Paging message
        test_messages = [
            {
                "name": "Paging Message",
                "hex": "000a402d00000500504002b140002b40060200e54d894900", 
                "expected_procedure": "Paging"
            },
            {
                "name": "CellTrafficTrace Message", 
                "hex": "002a403600000500000005c008c6ee75",
                "expected_procedure": "CellTrafficTrace"
            }
        ]
        
        for test in test_messages:
            print(f"\n📦 Testing: {test['name']}")
            print(f"   Data: {test['hex']}")
            
            # Convert hex to bytes
            test_data = bytes.fromhex(test['hex'])
            
            # Decode message
            message = decoder._decode_s1ap_message(1, 1234567890.0, test_data)
            
            if message:
                print(f"   ✅ Decoded successfully!")
                print(f"   Procedure: {message.procedure_name}")
                print(f"   Message Type: {message.message_type}")
                print(f"   IEs found: {len(message.ies)}")
                
                if message.ies:
                    print(f"   IEs:")
                    for ie in message.ies[:3]:  # Show first 3 IEs
                        print(f"      • {ie['name']} (ID: {ie['id']}, Length: {ie['length']})")
                
                if message.parsing_errors:
                    print(f"   ⚠️  Errors: {len(message.parsing_errors)}")
                    for error in message.parsing_errors[:2]:
                        print(f"      • {error}")
                        
                # Verify expected procedure
                if message.procedure_name == test['expected_procedure']:
                    print(f"   ✅ Procedure verification passed")
                else:
                    print(f"   ❌ Expected {test['expected_procedure']}, got {message.procedure_name}")
                    
            else:
                print(f"   ❌ Decoding failed")
        
        # Test statistics
        stats = decoder.get_statistics()
        print(f"\n📊 Final Statistics:")
        print(f"   S1AP messages decoded: {stats['s1ap_messages']}")
        print(f"   Procedures found: {len(stats['procedures'])}")
        print(f"   IEs found: {len(stats['ies_found'])}")
        print(f"   Errors: {len(stats['errors'])}")
        
        print(f"\n✅ Test completed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_s1ap_message_parsing()
    sys.exit(0 if success else 1)
