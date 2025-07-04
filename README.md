# S1AP Packet Decoder

A Python-based decoder for S1AP (S1 Application Protocol) messages extracted from PCAP files.

## Overview

This project provides a comprehensive solution for parsing and analyzing S1AP messages according to the 3GPP TS 36.413 specification. It can extract S1AP messages from PCAP files, decode all Information Elements (IEs), and provide detailed analysis of the protocol messages.

## Features

- **PCAP File Support**: Parse PCAP files to extract network packets
- **SCTP Layer Processing**: Extract S1AP payload from SCTP chunks
- **S1AP Message Decoding**: Full support for all S1AP procedure codes
- **Information Element Analysis**: Decode and analyze all standard IEs
- **ASN.1 PER Compliance**: Proper handling of ASN.1 Packed Encoding Rules
- **Wireshark Validation**: Results validated against Wireshark captures
- **Comprehensive Logging**: Detailed error reporting and debugging

## Project Structure

```
s1ap_new/
├── src/
│   ├── s1ap_decoder/        # Main decoder components
│   │   ├── __init__.py
│   │   ├── core.py          # Core S1AP decoder
│   │   └── ie_analyzer.py   # Information Element analyzer
│   ├── parsers/             # Network parsing components
│   │   ├── __init__.py
│   │   ├── pcap_parser.py   # PCAP file parser
│   │   └── sctp_parser.py   # SCTP layer parser
│   └── protocols/           # Protocol definitions
│       ├── __init__.py
│       ├── s1ap_constants.py # S1AP constants and mappings
│       └── ie_definitions.py # IE definitions and types
├── tests/                   # Unit tests
├── examples/                # Usage examples
├── requirements.txt         # Dependencies
└── README.md               # This file
```

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd s1ap_new
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Quick Start

```python
from src.s1ap_decoder import S1APDecoder

# Create decoder instance
decoder = S1APDecoder()

# Parse PCAP file
results = decoder.parse_pcap_file("path/to/your/file.pcap")

# Display results
for packet in results:
    if packet.has_s1ap:
        print(f"Procedure: {packet.procedure_name}")
        print(f"IEs found: {len(packet.ies)}")
        for ie in packet.ies:
            print(f"  - {ie.name}: {ie.value}")
```

## Usage Examples

See the `examples/` directory for detailed usage examples:
- `basic_parsing.py` - Simple PCAP parsing
- `ie_analysis.py` - Detailed IE analysis
- `batch_processing.py` - Process multiple files

## Testing

Run the test suite:
```bash
pytest tests/
```

## Contributing

1. Follow PEP 8 style guidelines
2. Add type hints to all functions
3. Include comprehensive docstrings
4. Write unit tests for new features
5. Validate against real Wireshark captures

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## References

- 3GPP TS 36.413: S1 Application Protocol (S1AP)
- ITU-T X.691: ASN.1 Packed Encoding Rules (PER)
- Wireshark S1AP Dissector Documentation
