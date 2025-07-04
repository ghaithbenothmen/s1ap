"""
SCTP Parser
Handles parsing of SCTP (Stream Control Transmission Protocol) packets to extract S1AP payload
"""

import struct
from typing import List, Optional, Tuple, Dict, Any
from dataclasses import dataclass

@dataclass
class SCTPChunk:
    """SCTP Chunk information"""
    type: int
    flags: int
    length: int
    data: bytes
    
    @property
    def type_name(self) -> str:
        """Get human-readable chunk type name"""
        chunk_types = {
            0: "DATA", 1: "INIT", 2: "INIT_ACK", 3: "SACK",
            4: "HEARTBEAT", 5: "HEARTBEAT_ACK", 6: "ABORT", 7: "SHUTDOWN",
            8: "SHUTDOWN_ACK", 9: "ERROR", 10: "COOKIE_ECHO", 11: "COOKIE_ACK"
        }
        return chunk_types.get(self.type, f"UNKNOWN_{self.type}")

@dataclass 
class SCTPDataChunk:
    """SCTP DATA Chunk with additional fields"""
    tsn: int
    stream_id: int
    stream_sequence: int
    ppid: int
    payload: bytes
    
    @property
    def ppid_name(self) -> str:
        """Get protocol name from PPID"""
        ppid_names = {
            18: "S1AP",
            59: "S1AP_EPC"
        }
        return ppid_names.get(self.ppid, f"PPID_{self.ppid}")
    
    @property
    def is_s1ap(self) -> bool:
        """Check if this chunk contains S1AP data"""
        return self.ppid in [18, 59]

@dataclass
class SCTPInfo:
    """Complete SCTP packet information"""
    src_port: int
    dst_port: int
    verification_tag: int
    checksum: int
    chunks: List[SCTPChunk]
    data_chunks: List[SCTPDataChunk]
    
    @property
    def has_s1ap(self) -> bool:
        """Check if packet contains S1AP data"""
        return any(chunk.is_s1ap for chunk in self.data_chunks)
    
    @property
    def s1ap_payloads(self) -> List[bytes]:
        """Get all S1AP payloads from this packet"""
        return [chunk.payload for chunk in self.data_chunks if chunk.is_s1ap]

class SCTPParser:
    """SCTP packet parser for S1AP extraction"""
    
    def __init__(self):
        pass
    
    def parse_sctp_packet(self, data: bytes) -> Optional[SCTPInfo]:
        """
        Parse SCTP packet and extract chunks
        
        Args:
            data: Raw SCTP packet data
            
        Returns:
            SCTPInfo or None if parsing fails
        """
        if len(data) < 12:
            return None
            
        try:
            # Parse SCTP common header
            src_port, dst_port, verification_tag, checksum = struct.unpack('>HHLL', data[0:12])
            
            # Parse chunks
            chunks = []
            data_chunks = []
            offset = 12
            
            while offset < len(data):
                chunk_info = self._parse_chunk(data, offset)
                if not chunk_info:
                    break
                    
                chunk, chunk_length = chunk_info
                chunks.append(chunk)
                
                # If it's a DATA chunk, parse additional fields
                if chunk.type == 0:  # DATA chunk
                    data_chunk = self._parse_data_chunk(chunk.data)
                    if data_chunk:
                        data_chunks.append(data_chunk)
                
                # Move to next chunk (with padding)
                offset += self._padded_length(chunk_length)
            
            return SCTPInfo(
                src_port=src_port,
                dst_port=dst_port, 
                verification_tag=verification_tag,
                checksum=checksum,
                chunks=chunks,
                data_chunks=data_chunks
            )
            
        except Exception:
            return None
    
    def _parse_chunk(self, data: bytes, offset: int) -> Optional[Tuple[SCTPChunk, int]]:
        """Parse a single SCTP chunk"""
        if offset + 4 > len(data):
            return None
            
        try:
            chunk_type = data[offset]
            chunk_flags = data[offset + 1]
            chunk_length = struct.unpack('>H', data[offset + 2:offset + 4])[0]
            
            if chunk_length < 4:
                return None
                
            chunk_data_length = chunk_length - 4
            chunk_end = offset + 4 + chunk_data_length
            
            if chunk_end > len(data):
                return None
                
            chunk_data = data[offset + 4:chunk_end]
            
            chunk = SCTPChunk(
                type=chunk_type,
                flags=chunk_flags,
                length=chunk_length,
                data=chunk_data
            )
            
            return chunk, chunk_length
            
        except Exception:
            return None
    
    def _parse_data_chunk(self, chunk_data: bytes) -> Optional[SCTPDataChunk]:
        """Parse SCTP DATA chunk payload"""
        if len(chunk_data) < 12:
            return None
            
        try:
            # Parse DATA chunk header
            tsn = struct.unpack('>L', chunk_data[0:4])[0]
            stream_id = struct.unpack('>H', chunk_data[4:6])[0]
            stream_sequence = struct.unpack('>H', chunk_data[6:8])[0]
            ppid = struct.unpack('>L', chunk_data[8:12])[0]
            
            # Payload starts after 12-byte header
            payload = chunk_data[12:]
            
            return SCTPDataChunk(
                tsn=tsn,
                stream_id=stream_id,
                stream_sequence=stream_sequence,
                ppid=ppid,
                payload=payload
            )
            
        except Exception:
            return None
    
    def _padded_length(self, length: int) -> int:
        """Calculate padded length (SCTP chunks are padded to 4-byte boundary)"""
        return (length + 3) & ~3
    
    def extract_s1ap_messages(self, sctp_info: SCTPInfo) -> List[bytes]:
        """Extract all S1AP messages from SCTP packet"""
        return sctp_info.s1ap_payloads
    
    def is_s1ap_port(self, sctp_info: SCTPInfo) -> bool:
        """Check if SCTP packet uses S1AP ports (36412)"""
        return sctp_info.src_port == 36412 or sctp_info.dst_port == 36412
