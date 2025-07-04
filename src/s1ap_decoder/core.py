"""
S1AP Core Decoder
Main decoder for S1AP messages according to 3GPP TS 36.413
"""

import struct
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

from protocols.s1ap_constants import S1AP_MESSAGE_TYPES, S1AP_PROCEDURES, S1AP_CRITICALITY
from protocols.ie_definitions import get_ie_name, get_ie_definition
from parsers.pcap_parser import PCAPParser, PacketInfo
from parsers.sctp_parser import SCTPParser
from s1ap_decoder.ie_analyzer import InformationElementAnalyzer

@dataclass
class S1APMessage:
    """S1AP Message structure"""
    packet_number: int
    timestamp: float
    message_type: str
    procedure_code: int
    procedure_name: str
    criticality: str
    raw_data: bytes
    ies: List[Dict[str, Any]]
    parsing_errors: List[str]
    
    @property
    def ie_count(self) -> int:
        """Number of IEs found"""
        return len(self.ies)
    
    @property
    def has_errors(self) -> bool:
        """Check if message has parsing errors"""
        return len(self.parsing_errors) > 0

class S1APDecoder:
    """Main S1AP decoder class"""
    
    def __init__(self):
        self.pcap_parser = PCAPParser()
        self.sctp_parser = SCTPParser()
        self.ie_analyzer = InformationElementAnalyzer()
        self.stats = {
            "total_packets": 0,
            "sctp_packets": 0,
            "s1ap_messages": 0,
            "procedures": {},
            "ies_found": {},
            "errors": []
        }
    
    def parse_pcap_file(self, filename: str, max_packets: Optional[int] = None) -> List[S1APMessage]:
        """
        Parse PCAP file and extract S1AP messages
        
        Args:
            filename: Path to PCAP file
            max_packets: Maximum number of packets to process
            
        Returns:
            List of S1AP messages found
        """
        s1ap_messages = []
        
        try:
            for packet in self.pcap_parser.parse_file(filename, max_packets):
                self.stats["total_packets"] += 1
                
                # Parse Ethernet frame
                eth_info = self.pcap_parser.parse_ethernet_frame(packet.data)
                if not eth_info or eth_info.ethertype != 0x0800:  # IPv4
                    continue
                
                # Parse IP packet
                ip_info = self.pcap_parser.parse_ip_packet(eth_info.payload)
                if not ip_info or not self.pcap_parser.is_sctp_packet(ip_info):
                    continue
                
                self.stats["sctp_packets"] += 1
                
                # Parse SCTP packet
                sctp_info = self.sctp_parser.parse_sctp_packet(ip_info.payload)
                if not sctp_info or not sctp_info.has_s1ap:
                    continue
                
                # Extract S1AP messages
                for s1ap_payload in sctp_info.s1ap_payloads:
                    message = self._decode_s1ap_message(
                        packet.number, packet.timestamp, s1ap_payload
                    )
                    if message:
                        s1ap_messages.append(message)
                        self.stats["s1ap_messages"] += 1
                        
        except Exception as e:
            self.stats["errors"].append(f"PCAP parsing error: {e}")
        
        return s1ap_messages
    
    def _decode_s1ap_message(self, packet_num: int, timestamp: float, data: bytes) -> Optional[S1APMessage]:
        """
        Decode a single S1AP message
        
        Args:
            packet_num: Packet number from PCAP
            timestamp: Packet timestamp  
            data: Raw S1AP message data
            
        Returns:
            S1APMessage or None if decoding fails
        """
        if len(data) < 4:
            return None
            
        try:
            # Parse S1AP header
            msg_type = data[0]
            procedure_code = data[1] 
            criticality = data[2]
            
            # Get readable names
            message_type = S1AP_MESSAGE_TYPES.get(msg_type, f"Unknown_0x{msg_type:02x}")
            procedure_name = S1AP_PROCEDURES.get(procedure_code, f"Unknown_Proc_{procedure_code}")
            criticality_name = S1AP_CRITICALITY.get(criticality & 0xC0, f"Unknown_0x{criticality:02x}")
            
            # Update statistics
            self.stats["procedures"][procedure_name] = self.stats["procedures"].get(procedure_name, 0) + 1
            
            # Parse length and find IE data
            ie_offset = 3
            if ie_offset < len(data):
                length_byte = data[ie_offset]
                ie_offset += 1
                
                # Handle different length encodings
                if length_byte & 0x80:
                    # Extended length encoding
                    if length_byte == 0x80:
                        # Indefinite length - not supported
                        pass
                    else:
                        # Multi-byte length
                        length_octets = length_byte & 0x7F
                        if ie_offset + length_octets <= len(data):
                            ie_offset += length_octets
            
            # Parse IEs
            parsing_errors = []
            ies = []
            
            if ie_offset < len(data):
                ie_data = data[ie_offset:]
                ies, ie_errors = self._parse_ies(ie_data)
                parsing_errors.extend(ie_errors)
                
                # Update IE statistics
                for ie in ies:
                    ie_name = ie.get("name", "Unknown")
                    self.stats["ies_found"][ie_name] = self.stats["ies_found"].get(ie_name, 0) + 1
            
            return S1APMessage(
                packet_number=packet_num,
                timestamp=timestamp,
                message_type=message_type,
                procedure_code=procedure_code,
                procedure_name=procedure_name,
                criticality=criticality_name,
                raw_data=data,
                ies=ies,
                parsing_errors=parsing_errors
            )
            
        except Exception as e:
            self.stats["errors"].append(f"S1AP decoding error: {e}")
            return None
    
    def _parse_ies(self, ie_data: bytes) -> Tuple[List[Dict[str, Any]], List[str]]:
        """
        Parse Information Elements from S1AP message
        
        Args:
            ie_data: Raw IE data
            
        Returns:
            Tuple of (IE list, error list)
        """
        ies = []
        errors = []
        pos = 0
        
        try:
            # Check for IE container format
            if len(ie_data) >= 3 and ie_data[0:2] == b'\x00\x00':
                # Standard 3-byte container: [00 00 count]
                ie_count = ie_data[2]
                pos = 3
                print(f"[DEBUG] Found IE container with {ie_count} IEs")
            elif len(ie_data) >= 4 and ie_data[0:3] == b'\x00\x00\x00':
                # 4-byte container: [00 00 00 count]  
                ie_count = ie_data[3]
                pos = 4
                print(f"[DEBUG] Found 4-byte IE container with {ie_count} IEs")
            else:
                # Direct IE data or other format
                ie_count = 5  # Estimate
                pos = 0
                print(f"[DEBUG] Direct IE parsing, estimating {ie_count} IEs")
            
            # Parse individual IEs
            parsed_count = 0
            max_attempts = min(ie_count + 2, 10)  # Safety limit
            
            while pos < len(ie_data) - 4 and parsed_count < max_attempts:
                ie_result = self._parse_single_ie(ie_data, pos)
                
                if ie_result["success"]:
                    ies.append(ie_result["ie"])
                    pos = ie_result["next_position"]
                    parsed_count += 1
                    print(f"[DEBUG] Parsed IE #{parsed_count}: {ie_result['ie']['name']}")
                else:
                    errors.append(f"IE parsing failed at position {pos}: {ie_result['error']}")
                    # Try to advance past the error
                    pos += 4
                    if pos >= len(ie_data):
                        break
                        
        except Exception as e:
            errors.append(f"IE container parsing error: {e}")
        
        print(f"[DEBUG] IE parsing complete: {len(ies)} IEs parsed, {len(errors)} errors")
        return ies, errors
    
    def _parse_single_ie(self, data: bytes, pos: int) -> Dict[str, Any]:
        """
        Parse a single Information Element
        
        Args:
            data: IE data buffer
            pos: Current position
            
        Returns:
            Dictionary with parsing result
        """
        try:
            if pos + 4 > len(data):
                return {"success": False, "error": "Not enough data for IE header"}
            
            # Parse IE header: [ID:2][Criticality:1][Length:1][Value:Length]
            ie_id = struct.unpack('>H', data[pos:pos+2])[0]
            criticality = data[pos+2]
            length = data[pos+3]
            
            # Calculate value position and check bounds
            value_pos = pos + 4
            value_end = value_pos + length
            
            if value_end > len(data):
                return {"success": False, "error": f"IE value extends beyond data (need {length} bytes)"}
            
            # Extract value
            value_data = data[value_pos:value_end]
            
            # Get IE information
            ie_name = get_ie_name(ie_id)
            criticality_name = S1AP_CRITICALITY.get(criticality & 0xC0, "unknown")
            
            # Analyze IE content
            analyzed_content = self.ie_analyzer.analyze_ie(ie_id, value_data)
            
            ie_info = {
                "id": ie_id,
                "name": ie_name,
                "criticality": criticality_name,
                "length": length,
                "value_hex": value_data.hex(),
                "analyzed_content": analyzed_content,
                "debug_info": {
                    "position": pos,
                    "criticality_byte": f"0x{criticality:02x}",
                    "value_start": value_pos,
                    "value_end": value_end
                }
            }
            
            return {
                "success": True,
                "ie": ie_info,
                "next_position": value_end
            }
            
        except Exception as e:
            return {"success": False, "error": f"Exception parsing IE: {e}"}
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get parsing statistics"""
        return self.stats.copy()
    
    def reset_statistics(self):
        """Reset parsing statistics"""
        self.stats = {
            "total_packets": 0,
            "sctp_packets": 0, 
            "s1ap_messages": 0,
            "procedures": {},
            "ies_found": {},
            "errors": []
        }
