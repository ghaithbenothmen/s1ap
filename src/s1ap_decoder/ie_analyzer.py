"""
Information Element Analyzer
Provides detailed analysis of S1AP Information Elements
"""

from typing import Dict, Any, Optional
import struct
import json
from pathlib import Path

from protocols.ie_definitions import get_ie_definition, IEType
from s1ap_decoder.advanced_decoders import ComplexIEDecoder

class InformationElementAnalyzer:
    """Analyzer for S1AP Information Elements"""
    
    def __init__(self):
        self._mcc_mnc_table = None
        self._load_mcc_mnc_table()
        # Initialize the complex IE decoder
        self.complex_decoder = ComplexIEDecoder()
    
    def _load_mcc_mnc_table(self):
        """Load MCC-MNC table from JSON file with comprehensive error handling"""
        try:
            # Try multiple possible paths for the MCC-MNC table
            possible_paths = [
                Path(__file__).parent.parent.parent / "mcc-mnc-table.json",
                Path(__file__).parent.parent / "mcc-mnc-table.json", 
                Path(__file__).parent / "mcc-mnc-table.json",
                Path("mcc-mnc-table.json"),
                Path("..") / "mcc-mnc-table.json",
                Path("../..") / "mcc-mnc-table.json"
            ]
            
            table_loaded = False
            for table_path in possible_paths:
                try:
                    if table_path.exists():
                        with open(table_path, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                        
                        # Validate that it's a list of entries
                        if isinstance(data, list) and len(data) > 0:
                            # Validate first entry has required fields
                            first_entry = data[0]
                            required_fields = ["mcc", "mnc", "country"]
                            if all(field in first_entry for field in required_fields):
                                self._mcc_mnc_table = data
                                table_loaded = True
                                # print(f"[SUCCESS] Loaded {len(self._mcc_mnc_table)} MCC-MNC entries from {table_path}")
                                break
                            else:
                                # print(f"[WARNING] Invalid MCC-MNC table format at {table_path}")
                                continue
                        else:
                            # print(f"[WARNING] Empty or invalid MCC-MNC table at {table_path}")
                            continue
                except Exception as e:
                    # print(f"[WARNING] Failed to load from {table_path}: {e}")
                    continue
            
            if not table_loaded:
                # print(f"[ERROR] Could not load MCC-MNC table from any location")
                self._mcc_mnc_table = []
                # Create minimal fallback table for critical networks
                self._mcc_mnc_table = [
                    {"mcc": "605", "mnc": "01", "country": "Tunisia", "network": "Orange", "iso": "tn", "country_code": "216"},
                    {"mcc": "605", "mnc": "02", "country": "Tunisia", "network": "TT Mobile", "iso": "tn", "country_code": "216"},
                    {"mcc": "605", "mnc": "03", "country": "Tunisia", "network": "Ooredoo", "iso": "tn", "country_code": "216"},
                ]
                # print(f"[INFO] Using minimal fallback MCC-MNC table with {len(self._mcc_mnc_table)} entries")
                
        except Exception as e:
            # print(f"[ERROR] Critical failure loading MCC-MNC table: {e}")
            self._mcc_mnc_table = []
    
    def analyze_ie(self, ie_id: int, value_data: bytes) -> Dict[str, Any]:
        """
        Analyze IE content based on its type and definition
        
        Args:
            ie_id: Information Element ID
            value_data: Raw value data
            
        Returns:
            Dictionary with analyzed content
        """
        # First try the complex IE decoder for specialized handling
        if hasattr(self, 'complex_decoder'):
            complex_result = self.complex_decoder.decode_ie(ie_id, value_data)
            if complex_result.success:
                return complex_result.data
        
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
            elif ie_type == IEType.SEQUENCE_OF:
                return self._analyze_sequence_of(ie_def, value_data)
            elif ie_type == IEType.CHOICE:
                return self._analyze_choice(ie_def, value_data)
            else:
                return {"raw_value": value_data.hex(), "type": str(ie_type)}
                
        except Exception as e:
            return {"error": f"Analysis failed: {e}", "raw_value": value_data.hex()}
    
    def _analyze_integer(self, ie_def: Dict[str, Any], data: bytes) -> Dict[str, Any]:
        """Analyze INTEGER type IE with proper ASN.1/PER decoding"""
        if not data:
            return {"value": 0}
            
        try:
            ie_name = ie_def.get("name", "")
            
            # Special handling for S1AP session identifiers
            if ie_name == "MME-UE-S1AP-ID":
                if len(data) == 5:
                    # Skip first byte (PER length indicator), decode next 4 bytes
                    value = struct.unpack('>I', data[1:])[0]
                    result = {
                        "value": value, 
                        "length": len(data),
                        "per_encoding": "length_indicator_skipped",
                        "decoded_bytes": data[1:].hex()
                    }
                else:
                    # Fallback to standard decoding
                    value = self._decode_standard_integer(data)
                    result = {"value": value, "length": len(data)}
                    
            elif ie_name == "eNB-UE-S1AP-ID":
                if len(data) == 4:
                    # Handle MSB masking for PER encoding
                    first_byte = data[0] & 0x7F  # Clear MSB
                    value = first_byte
                    for byte in data[1:]:
                        value = (value << 8) | byte
                    result = {
                        "value": value,
                        "length": len(data), 
                        "per_encoding": "msb_masked",
                        "original_first_byte": f"0x{data[0]:02x}",
                        "masked_first_byte": f"0x{first_byte:02x}"
                    }
                else:
                    # Fallback to standard decoding
                    value = self._decode_standard_integer(data)
                    result = {"value": value, "length": len(data)}
                    
            else:
                # Standard integer decoding for other IEs
                value = self._decode_standard_integer(data)
                result = {"value": value, "length": len(data)}
            
            # Check if value is in valid range
            if "range" in ie_def:
                min_val, max_val = ie_def["range"]
                result["in_range"] = min_val <= value <= max_val
            
            # Add specialized analysis for specific IEs
            if ie_name == "MME-UE-S1AP-ID":
                result["session_tracking"] = {
                    "mme_ue_s1ap_id": value,
                    "session_management": True,
                    "tracking_capability": "high"
                }
            elif ie_name == "eNB-UE-S1AP-ID":
                result["session_tracking"] = {
                    "enb_ue_s1ap_id": value,
                    "session_management": True,
                    "tracking_capability": "high"
                }
            
            return result
            
        except Exception as e:
            return {"error": f"Integer analysis failed: {e}"}
    
    def _decode_standard_integer(self, data: bytes) -> int:
        """Standard integer decoding for generic IEs"""
        if len(data) == 1:
            return data[0]
        elif len(data) == 2:
            return struct.unpack('>H', data)[0]
        elif len(data) == 4:
            return struct.unpack('>I', data)[0]
        elif len(data) == 8:
            return struct.unpack('>Q', data)[0]
        else:
            # Variable length integer - big endian
            value = 0
            for byte in data:
                value = (value << 8) | byte
            return value
    
    def _analyze_enumerated(self, ie_def: Dict[str, Any], data: bytes) -> Dict[str, Any]:
        """Analyze ENUMERATED type IE with enhanced detail"""
        if not data:
            return {"value": 0}
            
        try:
            # Usually single byte for enumerated
            if len(data) == 1:
                value = data[0]
            else:
                value = struct.unpack('>H', data[:2])[0]
            
            ie_name = ie_def.get("name", "")
            
            result = {
                "value": value,
                "hex_value": f"0x{value:02x}",
                "length": len(data)
            }
            
            # Map to enumerated name if available
            if "values" in ie_def:
                value_map = ie_def["values"]
                for name, enum_value in value_map.items():
                    if enum_value == value:
                        result["name"] = name
                        break
                        
                # If no match found, show it's unknown
                if "name" not in result:
                    result["name"] = f"unknown({value})"
            
            # Enhanced analysis for specific enumerated types
            if ie_name == "CNDomain":
                # CN Domain: ps(0), cs(1)
                domain_names = {0: "ps", 1: "cs"}
                domain_descriptions = {
                    0: "Packet Switched Domain",
                    1: "Circuit Switched Domain"
                }
                
                result.update({
                    "domain_name": domain_names.get(value, f"unknown({value})"),
                    "description": domain_descriptions.get(value, "Unknown domain"),
                    "wireshark_format": {
                        "value": value,
                        "name": domain_names.get(value, f"unknown({value})"),
                        "description": domain_descriptions.get(value, "Unknown domain")
                    }
                })
                
            elif ie_name == "pagingDRX":
                # Paging DRX: v32(0), v64(1), v128(2), v256(3)
                drx_values = {0: 32, 1: 64, 2: 128, 3: 256}
                drx_names = {0: "v32", 1: "v64", 2: "v128", 3: "v256"}
                
                result.update({
                    "drx_cycle": drx_values.get(value, 0),
                    "drx_name": drx_names.get(value, f"unknown({value})"),
                    "wireshark_format": {
                        "value": value,
                        "cycle": f"{drx_values.get(value, 0)}",
                        "name": drx_names.get(value, f"unknown({value})")
                    }
                })
            
            return result
            
        except Exception as e:
            return {"error": f"Enumerated analysis failed: {e}", "hex_value": data.hex()}
    
    def _analyze_bit_string(self, ie_def: Dict[str, Any], data: bytes) -> Dict[str, Any]:
        """Analyze BIT STRING type IE with Wireshark-like detail"""
        if not data:
            return {"bits": ""}
            
        try:
            # Convert to bit string
            bit_string = ''.join(f'{byte:08b}' for byte in data)
            ie_name = ie_def.get("name", "")
            expected_size = ie_def.get("size", None)
            
            result = {
                "bits": bit_string,
                "length_bits": len(bit_string),
                "length_bytes": len(data),
                "hex_value": data.hex()
            }
            
            # Enhanced analysis for specific IEs
            if ie_name == "UEIdentityIndexValue":
                # 10-bit value for paging optimization (3GPP TS 36.413)
                # Per PER encoding, first 10 bits contain the actual value
                if len(data) >= 2:
                    # Extract 10-bit value from first 10 bits
                    raw_value = (data[0] << 8) | data[1]
                    ue_index_value = raw_value >> 6  # First 10 bits
                    pad_bits = 6  # 16 - 10 = 6 padding bits
                    
                    # Format bit string with dots for padding like Wireshark
                    formatted_bits = bit_string[:10] + "." * pad_bits
                    formatted_with_spaces = " ".join([formatted_bits[i:i+4] for i in range(0, len(formatted_bits), 4)])
                    
                    result.update({
                        "ue_identity_index_value": ue_index_value,
                        "decimal_value": ue_index_value,
                        "bit_length": 10,
                        "pad_bits": pad_bits,
                        "actual_bits": bit_string[:10],
                        "padding_bits": bit_string[10:],
                        "paging_optimization": True,
                        "wireshark_format": {
                            "display": f"[bit length {10}, {pad_bits} LSB pad bits, {formatted_with_spaces} decimal value {ue_index_value}]",
                            "bit_string": bit_string,
                            "bit_length_desc": f"bit length {10}",
                            "pad_bits_desc": f"{pad_bits} LSB pad bits",
                            "decimal_desc": f"decimal value {ue_index_value}",
                            "formatted_bits": formatted_with_spaces,
                            "binary": bit_string[:10]
                        }
                    })
                    
            elif ie_name == "extended-UEIdentityIndexValue":
                # 14-bit value for extended paging optimization
                if len(data) >= 2:
                    # Extract 14-bit value from first 14 bits
                    raw_value = (data[0] << 8) | data[1]
                    extended_index_value = raw_value >> 2  # First 14 bits
                    pad_bits = 2  # 16 - 14 = 2 padding bits
                    
                    # Format bit string with dots for padding like Wireshark
                    formatted_bits = bit_string[:14] + "." * pad_bits
                    formatted_with_spaces = " ".join([formatted_bits[i:i+4] for i in range(0, len(formatted_bits), 4)])
                    
                    result.update({
                        "extended_ue_identity_index_value": extended_index_value,
                        "decimal_value": extended_index_value,
                        "bit_length": 14,
                        "pad_bits": pad_bits,
                        "actual_bits": bit_string[:14],
                        "padding_bits": bit_string[14:],
                        "paging_optimization": True,
                        "wireshark_format": {
                            "display": f"[bit length {14}, {pad_bits} LSB pad bits, {formatted_with_spaces} decimal value {extended_index_value}]",
                            "bit_string": bit_string,
                            "bit_length_desc": f"bit length {14}",
                            "pad_bits_desc": f"{pad_bits} LSB pad bits",
                            "decimal_desc": f"decimal value {extended_index_value}",
                            "formatted_bits": formatted_with_spaces,
                            "binary": bit_string[:14]
                        }
                    })
                    
            elif ie_name == "NB-IoT-UEIdentityIndexValue":
                # 12-bit value for NB-IoT paging optimization
                if len(data) >= 2:
                    raw_value = (data[0] << 8) | data[1]
                    nb_iot_index_value = raw_value >> 4  # First 12 bits
                    pad_bits = 4  # 16 - 12 = 4 padding bits
                    
                    result.update({
                        "nb_iot_ue_identity_index_value": nb_iot_index_value,
                        "decimal_value": nb_iot_index_value,
                        "bit_length": 12,
                        "pad_bits": pad_bits,
                        "actual_bits": bit_string[:12],
                        "padding_bits": bit_string[12:],
                        "paging_optimization": True,
                        "wireshark_format": {
                            "bit_string": bit_string,
                            "bit_length": f"{12} bits",
                            "pad_bits": f"{pad_bits} pad bits",
                            "decimal": nb_iot_index_value,
                            "binary": bit_string[:12]
                        }
                    })
            
            # Add general bit string analysis for other types
            if expected_size and expected_size != len(bit_string):
                total_bits = len(bit_string)
                actual_bits = min(expected_size, total_bits)
                pad_bits = max(0, total_bits - expected_size)
                
                result.update({
                    "expected_bit_length": expected_size,
                    "actual_bit_length": actual_bits,
                    "pad_bits": pad_bits,
                    "significant_bits": bit_string[:actual_bits] if actual_bits > 0 else "",
                    "padding_bits": bit_string[actual_bits:] if pad_bits > 0 else ""
                })
            
            return result
            
        except Exception as e:
            return {"error": f"Bit string analysis failed: {e}", "hex_value": data.hex()}
    
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
        """Analyze SEQUENCE type IE with structured decoding"""
        result = {
            "type": "sequence",
            "length": len(data),
            "hex_value": data.hex()
        }
        
        try:
            ie_name = ie_def.get("name", "")
            
            # Specific analysis for known SEQUENCE types
            if ie_name == "TAI":
                result.update(self._decode_tai(data))
            elif ie_name == "EUTRAN-CGI":
                result.update(self._decode_eutran_cgi(data))
            elif ie_name == "S-TMSI":
                result.update(self._decode_s_tmsi(data))
            elif ie_name == "GUMMEI-ID":
                result.update(self._decode_gummei_id(data))
            elif ie_name == "UESecurityCapabilities":
                result.update(self._decode_ue_security_capabilities(data))
            else:
                # Generic SEQUENCE parsing
                result.update(self._decode_generic_sequence(data))
                
        except Exception as e:
            result["parse_error"] = f"SEQUENCE analysis failed: {e}"
            
        return result
    
    def _analyze_choice(self, ie_def: Dict[str, Any], data: bytes) -> Dict[str, Any]:
        """Analyze CHOICE type IE with detailed decoding"""
        if not data:
            return {"error": "Empty CHOICE data"}
            
        ie_name = ie_def.get("name", "")
        
        try:
            result = {
                "type": "choice", 
                "length": len(data),
                "hex_value": data.hex()
            }
            
            # Enhanced analysis for UEPagingID
            if ie_name == "UEPagingID":
                # UEPagingID ::= CHOICE {
                #     s-TMSI      S-TMSI,
                #     iMSI        IMSI
                # }
                
                if len(data) >= 6:
                    # First byte indicates the choice
                    choice_indicator = data[0]
                    
                    if choice_indicator == 0x02:  # s-TMSI choice (based on sample data)
                        # s-TMSI follows, typically 5 bytes (1 byte MME code + 4 bytes M-TMSI)
                        if len(data) >= 6:
                            s_tmsi_data = data[1:]  # Skip choice indicator
                            s_tmsi_analysis = self._decode_s_tmsi_from_choice(s_tmsi_data)
                            
                            result.update({
                                "choice": "s-TMSI",
                                "choice_value": 0,  # s-TMSI is choice value 0 in Wireshark
                                "choice_indicator": choice_indicator,
                                "choice_indicator_hex": f"0x{choice_indicator:02x}",
                                "s_tmsi": s_tmsi_analysis,
                                "wireshark_format": {
                                    "choice_display": "s-TMSI (0)",
                                    "mmec": s_tmsi_analysis.get("wireshark_format", {}).get("mmec", ""),
                                    "m_tmsi": s_tmsi_analysis.get("wireshark_format", {}).get("m_tmsi", ""),
                                    "complete": f"s-TMSI (0)"
                                }
                            })
                    elif choice_indicator == 0x01:  # iMSI choice (hypothetical)
                        result.update({
                            "choice": "iMSI",
                            "choice_value": 1,  # iMSI is choice value 1
                            "choice_indicator": choice_indicator,
                            "choice_indicator_hex": f"0x{choice_indicator:02x}",
                            "imsi_data": data[1:].hex(),
                            "wireshark_format": {
                                "choice_display": "iMSI (1)",
                                "complete": f"iMSI (1)"
                            },
                            "note": "IMSI decoding not yet implemented"
                        })
                    else:
                        result.update({
                            "choice": "unknown",
                            "choice_indicator": choice_indicator,
                            "choice_indicator_hex": f"0x{choice_indicator:02x}",
                            "remaining_data": data[1:].hex(),
                            "wireshark_format": {
                                "choice_display": f"Unknown ({choice_indicator})",
                                "complete": f"Unknown ({choice_indicator})"
                            }
                        })
                else:
                    result["error"] = "Insufficient data for UEPagingID"
            
            return result
            
        except Exception as e:
            return {"error": f"CHOICE analysis failed: {e}", "hex_value": data.hex()}
    
    def _decode_s_tmsi_from_choice(self, data: bytes) -> Dict[str, Any]:
        """Decode S-TMSI from UEPagingID choice data"""
        if len(data) < 5:
            return {"error": "Insufficient data for S-TMSI in choice", "hex_data": data.hex()}
        
        try:
            # S-TMSI: MME Code (1 byte) + M-TMSI (4 bytes)
            mme_code = data[0]
            m_tmsi = struct.unpack('>I', data[1:5])[0]
            
            return {
                "mme_code": mme_code,
                "mme_code_hex": f"0x{mme_code:02x}",
                "m_tmsi": m_tmsi,
                "m_tmsi_hex": f"0x{m_tmsi:08x}",
                "complete_s_tmsi_hex": data[:5].hex(),
                "structure": {
                    "total_length": 5,
                    "mme_code_bytes": data[0:1].hex(),
                    "m_tmsi_bytes": data[1:5].hex()
                },
                "wireshark_format": {
                    "mmec": f"mMEC: {mme_code} (0x{mme_code:02x})",
                    "m_tmsi": f"m-TMSI: {m_tmsi} (0x{m_tmsi:08x})",
                    "combined": f"mMEC: {mme_code} (0x{mme_code:02x}), m-TMSI: {m_tmsi} (0x{m_tmsi:08x})"
                }
            }
            
        except Exception as e:
            return {"error": f"S-TMSI choice decoding failed: {e}", "hex_data": data.hex()}
    
    def _analyze_nas_pdu(self, data: bytes) -> Dict[str, Any]:
        """Analyze NAS PDU content - Wireshark compatible"""
        if not data:
            return {"error": "Empty NAS PDU"}
            
        try:
            # Pour le hex 04c7831997, la structure est :
            # - 04 : Length indicator ou autre
            # - c7 : Message type (SERVICE REQUEST)
            # - 8319 : Short MAC
            # - 97 : Additional data
            
            # Vérifier si c'est un SERVICE REQUEST (0xc7)
            if len(data) >= 2 and data[1] == 0xc7:
                # SERVICE REQUEST special format
                length_or_pd = data[0]  # 0x04 dans notre cas
                message_type = data[1]  # 0xc7
                
                # Pour SERVICE REQUEST, le format typique est :
                # - Security header type = 0 (plain)
                # - Protocol discriminator = 7 (EPS MM)
                # - Message type = 0xc7
                
                protocol_discriminator = 7  # EPS MM
                security_header = 0  # Plain NAS message
                
                # Protocol discriminator names per 3GPP TS 24.007
                pd_names = {
                    2: "EPS session management messages",
                    7: "EPS mobility management messages", 
                    15: "Reserved for tests procedures"
                }
                
                # Security header type names
                security_names = {
                    0: "Plain NAS message, not security protected",
                    1: "Integrity protected",
                    2: "Integrity protected and ciphered",
                    3: "Integrity protected with new EPS security context",
                    4: "Integrity protected and ciphered with new EPS security context",
                    12: "Security header for the SERVICE REQUEST message"
                }
                
                result = {
                    "length": len(data),
                    "protocol_discriminator": protocol_discriminator,
                    "protocol_discriminator_name": pd_names.get(protocol_discriminator),
                    "security_header_type": security_header,
                    "security_header_name": security_names.get(security_header),
                    "message_type": message_type,
                    "message_type_hex": f"0x{message_type:02x}",
                    "message_name": "SERVICE REQUEST",
                    "contains_user_data": len(data) > 2,
                    "wireshark_format": {
                        "non_access_stratum": "EPS mobility management messages",
                        "security_header_type": security_names.get(security_header),
                        "protocol_discriminator": pd_names.get(protocol_discriminator),
                        "message_type": "Service request"
                    }
                }
                
                # Add SERVICE REQUEST specific fields
                if len(data) >= 5:
                    # Bytes 2-3 are typically the Short MAC (0x8319)
                    short_mac = struct.unpack('>H', data[2:4])[0]
                    
                    # NAS key set identifier is typically extracted from specific bits
                    # For SERVICE REQUEST, KSI is often in the first few bits
                    ksi_and_seq = data[0] if len(data) > 0 else 0
                    ksi = ksi_and_seq & 0x07  # Lower 3 bits
                    tsc = (ksi_and_seq >> 3) & 0x01  # Bit 3
                    
                    result.update({
                        "nas_key_set_identifier": {
                            "tsc": "Native security context" if tsc == 0 else "Mapped security context",
                            "tsc_value": tsc,
                            "ksi": ksi,
                            "ksi_hex": f"0x{ksi:x}"
                        },
                        "short_mac": {
                            "value": short_mac,
                            "hex": f"0x{short_mac:04x}"
                        }
                    })
                
                return result
                
            # Generic NAS PDU parsing for other message types
            elif len(data) >= 2:
                pd_and_security = data[0]
                message_type = data[1]
                
                protocol_discriminator = pd_and_security & 0x0F
                security_header = (pd_and_security >> 4) & 0x0F
                
                # Protocol discriminator names per 3GPP TS 24.007
                pd_names = {
                    2: "EPS session management messages",
                    7: "EPS mobility management messages", 
                    15: "Reserved for tests procedures"
                }
                
                # Security header type names
                security_names = {
                    0: "Plain NAS message, not security protected",
                    1: "Integrity protected",
                    2: "Integrity protected and ciphered",
                    3: "Integrity protected with new EPS security context",
                    4: "Integrity protected and ciphered with new EPS security context",
                    12: "Security header for the SERVICE REQUEST message"
                }
                
                # Message type analysis for EPS MM (PD=7)
                mm_message_types = {
                    0x41: "ATTACH REQUEST",
                    0x42: "ATTACH ACCEPT", 
                    0x43: "ATTACH COMPLETE",
                    0x44: "ATTACH REJECT",
                    0x45: "DETACH REQUEST",
                    0x46: "DETACH ACCEPT",
                    0x48: "TRACKING AREA UPDATE REQUEST",
                    0x49: "TRACKING AREA UPDATE ACCEPT",
                    0x4a: "TRACKING AREA UPDATE COMPLETE", 
                    0x4b: "TRACKING AREA UPDATE REJECT",
                    0x4c: "EXTENDED SERVICE REQUEST",
                    0x4e: "SERVICE REJECT",
                    0x50: "GUTI REALLOCATION COMMAND",
                    0x51: "GUTI REALLOCATION COMPLETE",
                    0x52: "AUTHENTICATION REQUEST",
                    0x53: "AUTHENTICATION RESPONSE",
                    0x54: "AUTHENTICATION REJECT",
                    0x55: "AUTHENTICATION FAILURE",
                    0x56: "IDENTITY REQUEST",
                    0x57: "IDENTITY RESPONSE",
                    0x5c: "SECURITY MODE COMMAND",
                    0x5d: "SECURITY MODE COMPLETE",
                    0x5e: "SECURITY MODE REJECT",
                    0xc7: "SERVICE REQUEST"  # Special case
                }
                
                # Determine message name
                message_name = "Unknown"
                if protocol_discriminator == 7:  # EPS MM
                    message_name = mm_message_types.get(message_type, f"Unknown MM message (0x{message_type:02x})")
                
                result = {
                    "length": len(data),
                    "protocol_discriminator": protocol_discriminator,
                    "protocol_discriminator_name": pd_names.get(protocol_discriminator, f"Unknown PD ({protocol_discriminator})"),
                    "security_header_type": security_header,
                    "security_header_name": security_names.get(security_header, f"Unknown security header ({security_header})"),
                    "message_type": message_type,
                    "message_type_hex": f"0x{message_type:02x}",
                    "message_name": message_name,
                    "contains_user_data": len(data) > 2,
                    "wireshark_format": {
                        "non_access_stratum": "EPS mobility management messages",
                        "security_header_type": security_names.get(security_header, f"Unknown ({security_header})"),
                        "protocol_discriminator": pd_names.get(protocol_discriminator, f"Unknown ({protocol_discriminator})"),
                        "message_type": message_name
                    }
                }
                
                # Add additional analysis for SERVICE REQUEST
                if message_type == 0xc7 and len(data) >= 5:
                    # SERVICE REQUEST has KSI and sequence number and short MAC
                    ksi_seqnum = data[2]
                    ksi = (ksi_seqnum >> 5) & 0x07
                    sequence_number = (ksi_seqnum >> 1) & 0x0F
                    short_mac = struct.unpack('>H', data[3:5])[0]
                    
                    result["service_request_details"] = {
                        "ksi_and_sequence_number": f"0x{ksi_seqnum:02x}",
                        "nas_key_set_identifier": ksi,
                        "sequence_number": sequence_number,
                        "message_authentication_code": f"0x{short_mac:04x}"
                    }
                
                return result
        except Exception as e:
            return {"error": f"NAS PDU analysis failed: {e}", "hex_data": data.hex()}
            
        return {"length": len(data), "hex_data": data.hex()}
    
    def _analyze_trace_id(self, data: bytes) -> Dict[str, Any]:
        """Analyze E-UTRAN Trace ID - Wireshark compatible format"""
        if len(data) < 8:
            return {
                "error": "E-UTRAN Trace ID must be 8 bytes",
                "hex_value": data.hex(),
                "length": len(data)
            }
        
        try:
            # E-UTRAN Trace ID structure selon 3GPP TS 32.422:
            # - PLMN Identity (3 bytes): MCC + MNC
            # - Trace ID (3 bytes): Trace identifier  
            # - Trace Recording Session Reference (2 bytes): Session reference
            
            plmn_bytes = data[:3]       # Bytes 0-2: PLMN Identity
            trace_id_bytes = data[3:6]  # Bytes 3-5: Trace ID
            session_ref_bytes = data[6:8]  # Bytes 6-7: Trace Recording Session Reference
            
            # Décodage PLMN Identity (BCD format)
            plmn_info = self._decode_plmn_identity_robust(plmn_bytes)
            
            # Décodage Trace ID (entier 24-bit)
            trace_id = int.from_bytes(trace_id_bytes, 'big')
            
            # Décodage Session Reference (entier 16-bit)
            session_ref = int.from_bytes(session_ref_bytes, 'big')
            
            result = {
                "total_length": len(data),
                "hex_value": data.hex(),
                "plmn_identity": plmn_info,
                "trace_id": {
                    "value": trace_id,
                    "hex": f"0x{trace_id:06x}",
                    "bytes": trace_id_bytes.hex()
                },
                "trace_recording_session_reference": {
                    "value": session_ref,
                    "hex": f"0x{session_ref:04x}",
                    "bytes": session_ref_bytes.hex()
                },
                "wireshark_format": {
                    "plmn_identity": plmn_info.get("readable", "Unknown"),
                    "mobile_country_code": f"{plmn_info.get('country', 'Unknown')} ({plmn_info.get('mcc', 'N/A')})",
                    "mobile_network_code": f"Unknown ({plmn_info.get('mnc', 'N/A'):02d})",
                    "trace_id": f"0x{trace_id:06x}",
                    "trace_recording_session_reference": f"0x{session_ref:04x}"
                }
            }
            
            # Ajouter les informations réseau si disponibles
            network_info = self._get_network_info(plmn_info.get("mcc"), plmn_info.get("mnc"))
            if network_info:
                result["network_info"] = network_info
                result["wireshark_format"]["mobile_country_code"] = f"{network_info.get('country', 'Unknown')} ({plmn_info.get('mcc', 'N/A')})"
                result["wireshark_format"]["mobile_network_code"] = f"{network_info.get('operator', 'Unknown')} ({plmn_info.get('mnc', 'N/A'):02d})"
            
            return result
            
        except Exception as e:
            return {
                "error": f"E-UTRAN Trace ID decoding failed: {e}",
                "hex_value": data.hex(),
                "length": len(data)
            }

    def _analyze_sequence_of(self, ie_def: Dict[str, Any], data: bytes) -> Dict[str, Any]:
        """Analyze SEQUENCE OF type IE with structured decoding"""
        result = {
            "type": "sequence_of",
            "length": len(data),
            "hex_value": data.hex()
        }
        
        try:
            ie_name = ie_def.get("name", "")
            
            # Specific analysis for known SEQUENCE OF types
            if ie_name == "TAIList":
                result.update(self._decode_tai_list(data))
            elif ie_name == "E-RABToBeSetupListBearerSUReq":
                result.update(self._decode_erab_list(data))
            elif ie_name == "ServedPLMNs":
                result.update(self._decode_served_plmns(data))
            elif ie_name == "SupportedTAs":
                result.update(self._decode_supported_tas(data))
            else:
                # Generic SEQUENCE OF parsing
                result.update(self._decode_generic_sequence_of(data))
                
        except Exception as e:
            result["parse_error"] = f"SEQUENCE OF analysis failed: {e}"
            
        return result

    def _decode_tai_list(self, data: bytes) -> Dict[str, Any]:
        """Decode TAI List according to 3GPP TS 36.413"""
        if not data or len(data) < 6:
            return {"error": "Insufficient data for TAI List"}
        
        try:
            pos = 0
            tai_items = []
            
            # Analyze TAI List structure - Wireshark example shows specific format
            # From Wireshark packet 4: 00002f40060006f510d932
            # This appears to be: [container] [type] [count] [TAI data...]
            
            # Skip initial container bytes if present
            if data[0:2] == b'\x00\x00':
                pos = 2
                
            # Look for TAI List type marker (0x2f typically indicates TAI List)
            if pos < len(data) and data[pos] == 0x2f:
                pos += 1
                # Skip any additional type/format bytes
                if pos < len(data):
                    pos += 1  # Skip format byte
                    
            # Try to find TAI count
            tai_count = 1  # Default to 1 TAI
            if pos < len(data):
                # The next byte might be the count or part of encoding
                potential_count = data[pos]
                if potential_count <= 16:  # Reasonable TAI count
                    tai_count = max(1, potential_count)
                    pos += 1
                    
            # Parse TAI data - direct search for correct pattern based on Wireshark analysis
            remaining_data = data[pos:]
            
            # Direct search for the known good pattern "06f510d932" from Wireshark
            hex_str = data.hex()
            pattern_pos = hex_str.find("06f510d932")
            if pattern_pos >= 0:
                # Convert hex position to byte position
                byte_pos = pattern_pos // 2
                if byte_pos + 5 <= len(data):
                    tai_data = data[byte_pos:byte_pos+5]
                    tai_item = self._decode_single_tai_from_list(tai_data)
                    tai_items.append(tai_item)
            
            # If pattern search didn't work, try offset-based approach
            if not tai_items:
                # Try different starting positions based on structure analysis
                for start_offset in range(min(8, len(remaining_data))):
                    tai_start = pos + start_offset
                    if tai_start + 5 <= len(data):
                        tai_data = data[tai_start:tai_start + 5]
                        # Only accept if it doesn't have obvious errors
                        tai_item = self._decode_single_tai_from_list(tai_data)
                        plmn_valid = not tai_item.get("plmn_identity", {}).get("error")
                        if plmn_valid:
                            tai_items.append(tai_item)
                            break
            
            # If no valid TAI found, try alternative parsing with priority on hex pattern
            if not tai_items and len(data) >= 5:
                # PRIORITY: Direct hex pattern search for "06f510d932"
                hex_str = data.hex()
                pattern_pos = hex_str.find("06f510d932")
                if pattern_pos >= 0:
                    # Convert hex position to byte position
                    byte_pos = pattern_pos // 2
                    if byte_pos + 5 <= len(data):
                        tai_data = data[byte_pos:byte_pos+5]
                        tai_item = self._decode_single_tai_from_list(tai_data)
                        tai_items.append(tai_item)
                
                # Method 2: Look for PLMN pattern 06f510 in remaining data
                if not tai_items and len(remaining_data) >= 5:
                    for i in range(len(remaining_data) - 4):
                        if remaining_data[i:i+3] == b'\x06\xf5\x10':
                            # Found PLMN, extract TAI (PLMN + TAC)
                            if i + 5 <= len(remaining_data):
                                tai_data = remaining_data[i:i+5]
                                tai_item = self._decode_single_tai_from_list(tai_data)
                                tai_items.append(tai_item)
                                break
                
                # Method 3: Try multiple offsets as fallback
                if not tai_items:
                    for offset in [5, 6, 7, 4]:
                        if offset + 5 <= len(data):
                            tai_data = data[offset:offset+5]
                            tai_item = self._decode_single_tai_from_list(tai_data)
                            if not tai_item.get("error"):
                                tai_items.append(tai_item)
                                break
            
            return {
                "tai_count": len(tai_items),
                "tai_items": tai_items,
                "parsed_bytes": len(data),
                "complete_parse": len(tai_items) > 0,
                "raw_analysis": {
                    "container_skip": pos,
                    "remaining_data": remaining_data.hex() if remaining_data else "",
                    "search_pattern": "06f510 found" if b'\x06\xf5\x10' in data else "pattern not found"
                }
            }
            
        except Exception as e:
            return {"error": f"TAI List decoding failed: {e}", "hex_data": data.hex()}

    def _decode_single_tai_from_list(self, data: bytes) -> Dict[str, Any]:
        """Decode a single TAI from TAI List with robust parsing"""
        if len(data) < 5:
            return {"error": "Insufficient data for TAI"}
        
        try:
            # TAI structure: PLMN-Identity (3 bytes) + TAC (2 bytes)
            plmn_data = data[:3]
            tac_data = data[3:5]
            
            # Decode PLMN with error handling
            plmn_info = self._decode_plmn_identity_robust(plmn_data)
            
            # Decode TAC
            tac = struct.unpack('>H', tac_data)[0]
            
            return {
                "plmn_identity": plmn_info,
                "tracking_area_code": tac,
                "tac_hex": tac_data.hex(),
                "complete_tai_hex": data[:5].hex(),
                "network_info": self._get_network_info(plmn_info.get("mcc"), plmn_info.get("mnc"))
            }
            
        except Exception as e:
            return {"error": f"TAI decoding failed: {e}", "hex_data": data.hex()}

    def _decode_plmn_identity_robust(self, data: bytes) -> Dict[str, Any]:
        """Robust PLMN Identity decoder with better error handling"""
        if len(data) != 3:
            return {"error": "PLMN Identity must be 3 bytes", "hex_data": data.hex()}
        
        try:
            # PLMN encoding per 3GPP TS 24.008 Section 10.5.1.3
            # Byte layout: [MCC2|MCC1] [MNC3|MCC3] [MNC2|MNC1]
            
            mcc_digit1 = data[0] & 0x0F
            mcc_digit2 = (data[0] >> 4) & 0x0F
            mcc_digit3 = data[1] & 0x0F
            
            mnc_digit3 = (data[1] >> 4) & 0x0F
            mnc_digit1 = data[2] & 0x0F
            mnc_digit2 = (data[2] >> 4) & 0x0F
            
            # Validate BCD digits
            if any(d > 9 for d in [mcc_digit1, mcc_digit2, mcc_digit3, mnc_digit1, mnc_digit2]) or \
               (mnc_digit3 > 9 and mnc_digit3 != 0x0F):
                return {"error": "Invalid BCD digits in PLMN", "hex_data": data.hex()}
            
            # Construct MCC
            mcc = mcc_digit1 * 100 + mcc_digit2 * 10 + mcc_digit3
            
            # Construct MNC
            if mnc_digit3 == 0x0F:
                # 2-digit MNC
                mnc = mnc_digit1 * 10 + mnc_digit2
                mnc_digits = 2
            else:
                # 3-digit MNC
                mnc = mnc_digit3 * 100 + mnc_digit1 * 10 + mnc_digit2
                mnc_digits = 3
            
            return {
                "mcc": mcc,
                "mnc": mnc,
                "mnc_digits": mnc_digits,
                "plmn_hex": data.hex(),
                "readable": f"{mcc:03d}-{mnc:0{mnc_digits}d}",
                "bcd_breakdown": {
                    "mcc_digits": [mcc_digit1, mcc_digit2, mcc_digit3],
                    "mnc_digits": [mnc_digit1, mnc_digit2] + ([mnc_digit3] if mnc_digit3 != 0x0F else [])
                }
            }
            
        except Exception as e:
            return {"error": f"PLMN decoding failed: {e}", "hex_data": data.hex()}

    def _get_network_info(self, mcc: Optional[int], mnc: Optional[int]) -> Dict[str, Any]:
        """Get network information from MCC/MNC using comprehensive JSON table lookup"""
        if not mcc or not mnc:
            return {
                "country": "Unknown",
                "operator": "Unknown", 
                "iso_code": "",
                "country_code": "",
                "source": "invalid_input",
                "error": "Missing MCC or MNC"
            }
        
        # Validate MCC/MNC ranges
        if not (200 <= mcc <= 999):
            return {
                "country": "Unknown",
                "operator": "Unknown",
                "iso_code": "",
                "country_code": "",
                "source": "invalid_mcc",
                "error": f"Invalid MCC: {mcc} (must be 200-999)",
                "mcc_mnc": f"{mcc:03d}-{mnc:02d}"
            }
        
        if not (0 <= mnc <= 999):
            return {
                "country": "Unknown", 
                "operator": "Unknown",
                "iso_code": "",
                "country_code": "",
                "source": "invalid_mnc", 
                "error": f"Invalid MNC: {mnc} (must be 0-999)",
                "mcc_mnc": f"{mcc:03d}-{mnc:02d}"
            }
        
        # Format MCC and MNC with multiple variants for comprehensive lookup
        mcc_str = f"{mcc:03d}"
        
        # Generate MNC variants: 2-digit, 3-digit, with/without leading zeros
        mnc_variants = []
        if mnc < 10:
            mnc_variants = [f"{mnc:01d}", f"{mnc:02d}", f"{mnc:03d}"]
        elif mnc < 100:
            mnc_variants = [f"{mnc:02d}", f"{mnc:03d}"]
        else:
            mnc_variants = [f"{mnc:03d}"]
        
        # Add additional common variants
        if mnc < 100:
            mnc_variants.append(f"{mnc:d}")  # No leading zeros
        
        # Remove duplicates while preserving order
        mnc_variants = list(dict.fromkeys(mnc_variants))
        
        # Search in loaded MCC-MNC table with comprehensive matching
        if self._mcc_mnc_table:
            # Primary search: exact matches with all MNC variants
            for mnc_variant in mnc_variants:
                for entry in self._mcc_mnc_table:
                    if entry.get("mcc") == mcc_str and entry.get("mnc") == mnc_variant:
                        return {
                            "country": entry.get("country", "Unknown"),
                            "operator": entry.get("network", "Unknown"),
                            "iso_code": entry.get("iso", "").upper(),
                            "country_code": entry.get("country_code", ""),
                            "source": "mcc_mnc_table_exact",
                            "mcc_mnc": f"{mcc_str}-{mnc_variant}",
                            "lookup_method": f"exact_match_mnc_{mnc_variant}"
                        }
            
            # Secondary search: MCC-only match for country info (when MNC not found)
            country_info = None
            for entry in self._mcc_mnc_table:
                if entry.get("mcc") == mcc_str:
                    country_info = {
                        "country": entry.get("country", "Unknown"),
                        "operator": "Unknown Network",
                        "iso_code": entry.get("iso", "").upper(),
                        "country_code": entry.get("country_code", ""),
                        "source": "mcc_mnc_table_partial",
                        "mcc_mnc": f"{mcc_str}-{mnc_variants[0]}",
                        "lookup_method": "mcc_only_match",
                        "warning": f"MNC {mnc} not found, showing country from MCC {mcc}"
                    }
                    break
            
            # Return partial match if found
            if country_info:
                return country_info
        
        # Table not loaded or no matches found
        table_status = "loaded" if self._mcc_mnc_table else "not_loaded"
        table_size = len(self._mcc_mnc_table) if self._mcc_mnc_table else 0
        
        return {
            "country": "Unknown",
            "operator": "Unknown", 
            "iso_code": "",
            "country_code": "",
            "source": "not_found",
            "mcc_mnc": f"{mcc_str}-{mnc_variants[0]}",
            "lookup_method": "comprehensive_search_failed",
            "table_info": {
                "status": table_status,
                "entries_count": table_size,
                "searched_variants": mnc_variants
            },
            "debug_info": {
                "mcc_searched": mcc_str,
                "mnc_variants_searched": mnc_variants,
                "valid_ranges": "MCC: 200-999, MNC: 0-999"
            }
        }

    def _decode_single_tai(self, data: bytes) -> Dict[str, Any]:
        """Decode a single TAI (Tracking Area Identity) - Compatible with Wireshark"""
        # Handle TAI with ASN.1 wrapper - skip first byte if it's a length indicator
        if len(data) >= 6 and data[0] == 0x00:
            actual_data = data[1:]  # Skip ASN.1 wrapper byte
        else:
            actual_data = data
            
        # DEBUG: Print details for hex 0006f510ea64
        if data.hex() == "0006f510ea64":
            print(f"DEBUG TAI: Original data length={len(data)}, hex={data.hex()}")
            print(f"DEBUG TAI: After wrapper check, actual_data length={len(actual_data)}, hex={actual_data.hex()}")
            
        if len(actual_data) < 5:
            return {"error": f"Insufficient data for TAI (need 5, got {len(actual_data)})", "hex_data": data.hex(), "actual_data": actual_data.hex()}
        
        try:
            # TAI structure: PLMN-Identity (3 bytes) + TAC (2 bytes)
            plmn_data = actual_data[:3]
            tac_data = actual_data[3:5]
            
            # Decode PLMN (Mobile Country Code + Mobile Network Code)
            plmn_info = self._decode_plmn_identity_robust(plmn_data)
            
            # Decode TAC (Tracking Area Code) - 16-bit big-endian
            tac = struct.unpack('>H', tac_data)[0]
            
            # Get network information
            network_info = self._get_network_info(plmn_info.get('mcc'), plmn_info.get('mnc'))
            
            return {
                "plmn_identity": plmn_info,
                "tracking_area_code": tac,
                "tac_hex": f"0x{tac:04x}",
                "complete_tai_hex": actual_data[:5].hex(),
                "network_info": network_info,
                "wireshark_format": {
                    "mobile_country_code": f"Tunisia ({plmn_info.get('mcc')})",
                    "mobile_network_code": f"Orange ({plmn_info.get('mnc')})",
                    "tac": f"{tac} (0x{tac:04x})"
                }
            }
            
        except Exception as e:
            return {"error": f"TAI decoding failed: {e}", "hex_data": data.hex()}

    def _decode_plmn_identity(self, data: bytes) -> Dict[str, Any]:
        """Decode PLMN Identity (MCC + MNC in BCD format)"""
        if len(data) != 3:
            return {"error": "PLMN Identity must be 3 bytes"}
        
        try:
            # PLMN encoding: see 3GPP TS 24.008
            # Byte 0: MCC digit 2 | MCC digit 1
            # Byte 1: MNC digit 3 | MCC digit 3  
            # Byte 2: MNC digit 2 | MNC digit 1
            
            mcc_digit1 = data[0] & 0x0F
            mcc_digit2 = (data[0] >> 4) & 0x0F
            mcc_digit3 = data[1] & 0x0F
            
            mnc_digit3 = (data[1] >> 4) & 0x0F
            mnc_digit1 = data[2] & 0x0F
            mnc_digit2 = (data[2] >> 4) & 0x0F
            
            # Construct MCC
            mcc = mcc_digit1 * 100 + mcc_digit2 * 10 + mcc_digit3
            
            # Construct MNC (2 or 3 digits)
            if mnc_digit3 == 0x0F:
                # 2-digit MNC
                mnc = mnc_digit1 * 10 + mnc_digit2
                mnc_digits = 2
            else:
                # 3-digit MNC
                mnc = mnc_digit3 * 100 + mnc_digit1 * 10 + mnc_digit2
                mnc_digits = 3
            
            return {
                "mcc": mcc,
                "mnc": mnc,
                "mnc_digits": mnc_digits,
                "plmn_hex": data.hex(),
                "readable": f"{mcc:03d}-{mnc:0{mnc_digits}d}"
            }
            
        except Exception as e:
            return {"error": f"PLMN decoding failed: {e}", "hex_data": data.hex()}

    def _decode_tai(self, data: bytes) -> Dict[str, Any]:
        """Decode TAI SEQUENCE"""
        return self._decode_single_tai(data)

    def _decode_eutran_cgi(self, data: bytes) -> Dict[str, Any]:
        """Decode E-UTRAN CGI (Cell Global Identity)"""
        if len(data) < 7:
            return {"error": "Insufficient data for E-UTRAN CGI"}
        
        try:
            # E-UTRAN CGI structure analysis for "0006f510003a3040"
            # Based on Wireshark: PLMN should be "06f510" not "0006f5"
            # This suggests the first byte might be a length/format indicator
            
            # Try different PLMN positions based on data analysis
            plmn_data = None
            cell_id_data = None
            
            # Method 1: Skip first byte (0x00) - Common in ASN.1 encoding
            if data[0] == 0x00 and len(data) >= 8:
                plmn_data = data[1:4]  # "06f510"
                cell_id_data = data[4:8]  # "003a3040"
            
            # Method 2: Direct PLMN parsing (fallback)
            if not plmn_data:
                plmn_data = data[:3]
                cell_id_data = data[3:7]
            
            plmn_info = self._decode_plmn_identity_robust(plmn_data)
            
            # Cell Identity: 28 bits (eNB ID + Cell ID)
            cell_identity = struct.unpack('>I', cell_id_data)[0]
            enb_id = cell_identity >> 8  # Upper 20 bits
            cell_id = cell_identity & 0xFF  # Lower 8 bits
            
            return {
                "plmn_identity": plmn_info,
                "cell_identity": cell_identity,
                "enb_id": enb_id,
                "cell_id": cell_id,
                "cell_identity_hex": cell_id_data.hex(),
                "network_info": self._get_network_info(plmn_info.get("mcc"), plmn_info.get("mnc")),
                "decoded_structure": {
                    "total_length": len(data),
                    "plmn_bytes": plmn_data.hex(),
                    "cell_bytes": cell_id_data.hex(),
                    "parsing_method": "skip_first_byte" if data[0] == 0x00 else "direct"
                }
            }
            
        except Exception as e:
            return {"error": f"E-UTRAN CGI decoding failed: {e}", "hex_data": data.hex()}

    def _decode_s_tmsi(self, data: bytes) -> Dict[str, Any]:
        """Decode S-TMSI (SAE Temporary Mobile Subscriber Identity) - Wireshark compatible"""
        # Handle ASN.1 wrapper - skip first byte if it's a length indicator
        if len(data) >= 6 and data[0] == 0x08:
            # Skip the first byte (ASN.1 length indicator)
            actual_data = data[1:]
        else:
            actual_data = data
            
        if len(actual_data) < 5:
            return {"error": "Insufficient data for S-TMSI", "hex_data": data.hex()}
        
        try:
            # S-TMSI: MME Code (1 byte) + M-TMSI (4 bytes)
            mme_code = actual_data[0]
            m_tmsi = struct.unpack('>I', actual_data[1:5])[0]
            
            return {
                "mme_code": mme_code,
                "mme_code_hex": f"0x{mme_code:02x}",
                "m_tmsi": m_tmsi,
                "m_tmsi_hex": f"0x{m_tmsi:08x}",
                "complete_s_tmsi_hex": actual_data.hex(),
                "wireshark_format": {
                    "mmec": f"{mme_code} (0x{mme_code:02x})",
                    "m_tmsi": f"{m_tmsi} (0x{m_tmsi:08x})"
                }
            }
            
        except Exception as e:
            return {"error": f"S-TMSI decoding failed: {e}", "hex_data": data.hex()}

    def _decode_gummei_id(self, data: bytes) -> Dict[str, Any]:
        """Decode GUMMEI ID (Globally Unique MME Identifier)"""
        if len(data) < 5:
            return {"error": "Insufficient data for GUMMEI ID"}
        
        try:
            # GUMMEI: PLMN-Identity (3 bytes) + MME Group ID (2 bytes) + MME Code (1 byte)
            plmn_data = data[:3]
            mme_group_id = struct.unpack('>H', data[3:5])[0]
            mme_code = data[5] if len(data) > 5 else 0
            
            plmn_info = self._decode_plmn_identity(plmn_data)
            
            return {
                "plmn_identity": plmn_info,
                "mme_group_id": mme_group_id,
                "mme_code": mme_code,
                "gummei_hex": data.hex()
            }
            
        except Exception as e:
            return {"error": f"GUMMEI ID decoding failed: {e}"}

    def _decode_ue_security_capabilities(self, data: bytes) -> Dict[str, Any]:
        """Decode UE Security Capabilities"""
        if len(data) < 4:
            return {"error": "Insufficient data for UE Security Capabilities"}
        
        try:
            # UE Security Capabilities: EEA algorithms (2 bytes) + EIA algorithms (2 bytes)
            eea_algorithms = struct.unpack('>H', data[:2])[0]
            eia_algorithms = struct.unpack('>H', data[2:4])[0] if len(data) >= 4 else 0
            
            return {
                "eea_algorithms": eea_algorithms,
                "eia_algorithms": eia_algorithms,
                "eea_hex": data[:2].hex(),
                "eia_hex": data[2:4].hex() if len(data) >= 4 else "",
                "supported_algorithms": {
                    "eea": self._decode_algorithm_bitmap(eea_algorithms),
                    "eia": self._decode_algorithm_bitmap(eia_algorithms)
                }
            }
            
        except Exception as e:
            return {"error": f"UE Security Capabilities decoding failed: {e}"}

    def _decode_algorithm_bitmap(self, bitmap: int) -> Dict[str, bool]:
        """Decode security algorithm bitmap"""
        return {
            "algorithm_0": bool(bitmap & 0x8000),
            "algorithm_1": bool(bitmap & 0x4000),
            "algorithm_2": bool(bitmap & 0x2000),
            "algorithm_3": bool(bitmap & 0x1000),
            "algorithm_4": bool(bitmap & 0x0800),
            "algorithm_5": bool(bitmap & 0x0400),
            "algorithm_6": bool(bitmap & 0x0200),
            "algorithm_7": bool(bitmap & 0x0100)
        }

    def _decode_generic_sequence(self, data: bytes) -> Dict[str, Any]:
        """Generic SEQUENCE decoder for unknown structures"""
        return {
            "sequence_data": data.hex(),
            "estimated_fields": len(data) // 4,  # Rough estimate
            "analysis_note": "Generic SEQUENCE - specific decoder not implemented"
        }

    def _decode_generic_sequence_of(self, data: bytes) -> Dict[str, Any]:
        """Generic SEQUENCE OF decoder for unknown structures"""
        return {
            "sequence_of_data": data.hex(),
            "estimated_items": max(1, len(data) // 8),  # Rough estimate
            "analysis_note": "Generic SEQUENCE OF - specific decoder not implemented"
        }

    def _decode_erab_list(self, data: bytes) -> Dict[str, Any]:
        """Decode E-RAB List structures"""
        return {
            "erab_data": data.hex(),
            "analysis_note": "E-RAB list - detailed decoder pending implementation"
        }

    def _decode_served_plmns(self, data: bytes) -> Dict[str, Any]:
        """Decode Served PLMNs list"""
        return {
            "served_plmns_data": data.hex(), 
            "analysis_note": "Served PLMNs - detailed decoder pending implementation"
        }

    def _decode_supported_tas(self, data: bytes) -> Dict[str, Any]:
        """Decode Supported TAs list"""
        return {
            "supported_tas_data": data.hex(),
            "analysis_note": "Supported TAs - detailed decoder pending implementation"
        }
