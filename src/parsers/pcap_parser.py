"""
PCAP File Parser
Handles reading and parsing of PCAP files to extract network packets
"""

import struct
import socket
from typing import List, Iterator, Optional, Tuple, Any
from dataclasses import dataclass
from datetime import datetime

@dataclass
class PacketInfo:
    """Information about a network packet"""
    number: int
    timestamp: float
    length: int
    original_length: int
    data: bytes

@dataclass
class EthernetInfo:
    """Ethernet frame information"""
    dst_mac: str
    src_mac: str  
    ethertype: int
    payload: bytes

@dataclass
class IPInfo:
    """IP packet information"""
    version: int
    header_length: int
    protocol: int
    src_ip: str
    dst_ip: str
    total_length: int
    payload: bytes

class PCAPParser:
    """PCAP file parser for network packet extraction"""
    
    def __init__(self):
        self.packet_count = 0
        
    def parse_file(self, filename: str, max_packets: Optional[int] = None) -> Iterator[PacketInfo]:
        """
        Parse PCAP file and yield packet information
        
        Args:
            filename: Path to PCAP file
            max_packets: Maximum number of packets to parse (None for all)
            
        Yields:
            PacketInfo: Information about each packet
        """
        try:
            with open(filename, 'rb') as f:
                # Read PCAP global header
                global_header = f.read(24)
                if len(global_header) < 24:
                    raise ValueError("Invalid PCAP file: header too short")
                
                # Parse global header
                magic, version_major, version_minor, thiszone, sigfigs, snaplen, network = \
                    struct.unpack('<LHHLLLL', global_header)
                
                if magic != 0xa1b2c3d4:
                    raise ValueError("Invalid PCAP file: wrong magic number")
                
                packet_num = 0
                
                # Read packets
                while True:
                    if max_packets and packet_num >= max_packets:
                        break
                        
                    # Read packet header
                    packet_header = f.read(16)
                    if len(packet_header) < 16:
                        break  # End of file
                    
                    ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<LLLL', packet_header)
                    
                    # Read packet data
                    packet_data = f.read(incl_len)
                    if len(packet_data) < incl_len:
                        break  # Incomplete packet
                    
                    packet_num += 1
                    timestamp = ts_sec + ts_usec / 1000000.0
                    
                    yield PacketInfo(
                        number=packet_num,
                        timestamp=timestamp,
                        length=incl_len,
                        original_length=orig_len,
                        data=packet_data
                    )
                    
        except Exception as e:
            raise RuntimeError(f"Error parsing PCAP file: {e}")
    
    def parse_ethernet_frame(self, data: bytes) -> Optional[EthernetInfo]:
        """
        Parse Ethernet frame
        
        Args:
            data: Raw packet data
            
        Returns:
            EthernetInfo or None if parsing fails
        """
        if len(data) < 14:
            return None
            
        try:
            # Unpack Ethernet header
            dst_mac_raw = data[0:6]
            src_mac_raw = data[6:12]
            ethertype = struct.unpack('>H', data[12:14])[0]
            
            # Format MAC addresses
            dst_mac = ':'.join(f'{b:02x}' for b in dst_mac_raw)
            src_mac = ':'.join(f'{b:02x}' for b in src_mac_raw)
            
            return EthernetInfo(
                dst_mac=dst_mac,
                src_mac=src_mac,
                ethertype=ethertype,
                payload=data[14:]
            )
            
        except Exception:
            return None
    
    def parse_ip_packet(self, data: bytes) -> Optional[IPInfo]:
        """
        Parse IPv4 packet
        
        Args:
            data: Raw IP packet data
            
        Returns:
            IPInfo or None if parsing fails
        """
        if len(data) < 20:
            return None
            
        try:
            # Parse IP header
            version_ihl = data[0]
            version = (version_ihl >> 4) & 0xF
            ihl = (version_ihl & 0xF) * 4
            
            if version != 4:
                return None  # Only IPv4 supported
                
            protocol = data[9]
            total_length = struct.unpack('>H', data[2:4])[0]
            src_ip = socket.inet_ntoa(data[12:16])
            dst_ip = socket.inet_ntoa(data[16:20])
            
            return IPInfo(
                version=version,
                header_length=ihl,
                protocol=protocol,
                src_ip=src_ip,
                dst_ip=dst_ip,
                total_length=total_length,
                payload=data[ihl:]
            )
            
        except Exception:
            return None
    
    def is_sctp_packet(self, ip_info: IPInfo) -> bool:
        """Check if IP packet contains SCTP (protocol 132)"""
        return ip_info.protocol == 132
