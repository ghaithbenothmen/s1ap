"""
Information Element Analyzer
Provides detailed analysis of S1AP Information Elements
"""

from typing import Dict, Any, Optional
import struct

from protocols.ie_definitions import get_ie_definition, IEType

class InformationElementAnalyzer:
    """Analyzer for S1AP Information Elements"""
    
    def __init__(self):
        pass
    
    def analyze_ie(self, ie_id: int, value_data: bytes) -> Dict[str, Any]:
        """
        Analyze IE content based on its type and definition
        
        Args:
            ie_id: Information Element ID
            value_data: Raw value data
            
        Returns:
            Dictionary with analyzed content
        """
        ie_def = get_ie_definition(ie_id)
        if not ie_def:
            return {"raw_value": value_data.hex()}
        
        try:
            # Dispatch to specific analyzer based on IE type
            ie_type = ie_def.get("type")
            
            if ie_type == IEType.INTEGER:
                return self._analyze_integer(ie_def, value_data)
            elif ie_type == IEType.ENUMERATED:
                return self._analyze_enumerated(ie_def, value_data)
            elif ie_type == IEType.BIT_STRING:
                return self._analyze_bit_string(ie_def, value_data)
            elif ie_type == IEType.OCTET_STRING:
                return self._analyze_octet_string(ie_def, value_data)
            elif ie_type == IEType.SEQUENCE:
                return self._analyze_sequence(ie_def, value_data)
            elif ie_type == IEType.CHOICE:
                return self._analyze_choice(ie_def, value_data)
            else:
                return {"raw_value": value_data.hex(), "type": str(ie_type)}
                
        except Exception as e:
            return {"error": f"Analysis failed: {e}", "raw_value": value_data.hex()}
    
    def _analyze_integer(self, ie_def: Dict[str, Any], data: bytes) -> Dict[str, Any]:
        """Analyze INTEGER type IE"""
        if not data:
            return {"value": 0}
            
        try:
            # Handle different integer sizes
            if len(data) == 1:
                value = data[0]
            elif len(data) == 2:
                value = struct.unpack('>H', data)[0]
            elif len(data) == 4:
                value = struct.unpack('>L', data)[0]
            elif len(data) == 8:
                value = struct.unpack('>Q', data)[0]
            else:
                # Variable length integer
                value = 0
                for byte in data:
                    value = (value << 8) | byte
            
            result = {"value": value, "length": len(data)}
            
            # Check if value is in valid range
            if "range" in ie_def:
                min_val, max_val = ie_def["range"]
                result["in_range"] = min_val <= value <= max_val
            
            # Add specialized analysis for specific IEs
            if ie_def["name"] == "MME-UE-S1AP-ID":
                result["session_tracking"] = {
                    "mme_ue_s1ap_id": value,
                    "session_management": True,
                    "tracking_capability": "high"
                }
            elif ie_def["name"] == "eNB-UE-S1AP-ID":
                result["session_tracking"] = {
                    "enb_ue_s1ap_id": value,
                    "session_management": True,
                    "tracking_capability": "high"
                }
            
            return result
            
        except Exception as e:
            return {"error": f"Integer analysis failed: {e}"}
    
    def _analyze_enumerated(self, ie_def: Dict[str, Any], data: bytes) -> Dict[str, Any]:
        """Analyze ENUMERATED type IE"""
        if not data:
            return {"value": 0}
            
        try:
            # Usually single byte for enumerated
            if len(data) == 1:
                value = data[0]
            else:
                value = struct.unpack('>H', data[:2])[0]
            
            result = {"value": value}
            
            # Map to enumerated name if available
            if "values" in ie_def:
                value_map = ie_def["values"]
                for name, enum_value in value_map.items():
                    if enum_value == value:
                        result["name"] = name
                        break
            
            return result
            
        except Exception as e:
            return {"error": f"Enumerated analysis failed: {e}"}
    
    def _analyze_bit_string(self, ie_def: Dict[str, Any], data: bytes) -> Dict[str, Any]:
        """Analyze BIT STRING type IE"""
        if not data:
            return {"bits": ""}
            
        try:
            # Convert to bit string
            bit_string = ''.join(f'{byte:08b}' for byte in data)
            
            result = {
                "bits": bit_string,
                "length_bits": len(bit_string),
                "length_bytes": len(data)
            }
            
            # Extract specific bit values for known IEs
            if ie_def["name"] == "UEIdentityIndexValue":
                # 10-bit value for paging optimization
                if len(data) >= 2:
                    value = (data[0] << 8 | data[1]) >> 6  # First 10 bits
                    result["ue_identity_index"] = value
                    result["paging_optimization"] = True
            
            return result
            
        except Exception as e:
            return {"error": f"Bit string analysis failed: {e}"}
    
    def _analyze_octet_string(self, ie_def: Dict[str, Any], data: bytes) -> Dict[str, Any]:
        """Analyze OCTET STRING type IE"""
        result = {
            "length": len(data),
            "hex_value": data.hex()
        }
        
        try:
            # Specialized analysis for specific IEs
            if ie_def["name"] == "NAS-PDU":
                result["nas_pdu"] = self._analyze_nas_pdu(data)
            elif ie_def["name"] == "E-UTRAN-Trace-ID":
                result["trace_id"] = self._analyze_trace_id(data)
            
            return result
            
        except Exception as e:
            return {"error": f"Octet string analysis failed: {e}", "hex_value": data.hex()}
    
    def _analyze_sequence(self, ie_def: Dict[str, Any], data: bytes) -> Dict[str, Any]:
        """Analyze SEQUENCE type IE"""
        return {
            "type": "sequence",
            "length": len(data),
            "hex_value": data.hex()
        }
    
    def _analyze_choice(self, ie_def: Dict[str, Any], data: bytes) -> Dict[str, Any]:
        """Analyze CHOICE type IE"""
        return {
            "type": "choice", 
            "length": len(data),
            "hex_value": data.hex()
        }
    
    def _analyze_nas_pdu(self, data: bytes) -> Dict[str, Any]:
        """Analyze NAS PDU content"""
        if not data:
            return {}
            
        try:
            # Basic NAS PDU structure
            if len(data) >= 2:
                pd_and_security = data[0]
                message_type = data[1]
                
                protocol_discriminator = pd_and_security & 0x0F
                security_header = (pd_and_security >> 4) & 0x0F
                
                return {
                    "length": len(data),
                    "protocol_discriminator": protocol_discriminator,
                    "security_header_type": security_header,
                    "message_type": message_type,
                    "contains_user_data": len(data) > 2
                }
        except Exception:
            pass
            
        return {"length": len(data)}
    
    def _analyze_trace_id(self, data: bytes) -> Dict[str, Any]:
        """Analyze E-UTRAN Trace ID"""
        if len(data) >= 8:
            return {
                "trace_reference": data[:3].hex(),
                "trace_recording_session": data[3:5].hex(),
                "additional_info": data[5:].hex()
            }
        return {"hex_value": data.hex()}
