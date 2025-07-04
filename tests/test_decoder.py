#!/usr/bin/env python3
"""
Test suite for S1AP decoder
"""

import pytest
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from s1ap_decoder.core import S1APDecoder
from protocols.s1ap_constants import S1AP_PROCEDURES, S1AP_MESSAGE_TYPES

def test_decoder_initialization():
    """Test that decoder initializes correctly"""
    decoder = S1APDecoder()
    assert decoder is not None
    assert decoder.stats["total_packets"] == 0

def test_s1ap_constants():
    """Test S1AP constants are loaded correctly"""
    assert 10 in S1AP_PROCEDURES  # Paging
    assert S1AP_PROCEDURES[10] == "Paging"
    assert 0x00 in S1AP_MESSAGE_TYPES  # InitiatingMessage

def test_message_parsing():
    """Test basic S1AP message parsing"""
    decoder = S1APDecoder()
    
    # Sample Paging message: 000a402d00000500504002b140002b40
    test_data = bytes.fromhex("000a402d00000500504002b140002b40")
    
    message = decoder._decode_s1ap_message(1, 1234567890.0, test_data)
    
    assert message is not None
    assert message.procedure_name == "Paging"
    assert message.message_type == "InitiatingMessage"
    assert message.procedure_code == 10

if __name__ == "__main__":
    pytest.main([__file__])
