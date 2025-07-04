"""
S1AP Information Element (IE) Definitions
Complete mapping of S1AP IEs according to 3GPP TS 36.413
"""

from typing import Dict, Any, Optional
from enum import Enum

class IEType(Enum):
    """IE Data Types"""
    INTEGER = "INTEGER"
    ENUMERATED = "ENUMERATED"
    BIT_STRING = "BIT STRING"
    OCTET_STRING = "OCTET STRING"
    SEQUENCE = "SEQUENCE"
    SEQUENCE_OF = "SEQUENCE OF"
    CHOICE = "CHOICE"
    BOOLEAN = "BOOLEAN"

# Complete S1AP IE Dictionary (3GPP TS 36.413)
S1AP_IES = {
    0: {
        "name": "MME-UE-S1AP-ID",
        "type": IEType.INTEGER,
        "range": (0, 4294967295),
        "description": "MME UE S1AP ID for session tracking"
    },
    1: {
        "name": "HandoverType", 
        "type": IEType.ENUMERATED,
        "values": {"intralte": 0, "ltetoutran": 1, "ltetogeran": 2, "utrantolte": 3, "gerantolte": 4},
        "description": "Type of handover procedure"
    },
    2: {
        "name": "Cause",
        "type": IEType.CHOICE,
        "choices": ["radioNetwork", "transport", "nas", "protocol", "misc"],
        "description": "Cause of failure or release"
    },
    3: {
        "name": "SourceID",
        "type": IEType.CHOICE,
        "choices": ["sourceENB-ID", "sourceRNC-ID"],
        "description": "Source identifier in handover"
    },
    4: {
        "name": "TargetID", 
        "type": IEType.CHOICE,
        "choices": ["targetENB-ID", "targetRNC-ID", "cGI"],
        "description": "Target identifier in handover"
    },
    5: {
        "name": "MME-UE-S1AP-ID",
        "type": IEType.INTEGER,
        "range": (0, 4294967295),
        "description": "MME UE S1AP ID (duplicate entry)"
    },
    8: {
        "name": "eNB-UE-S1AP-ID",
        "type": IEType.INTEGER, 
        "range": (0, 16777215),
        "description": "eNB UE S1AP ID for session tracking"
    },
    26: {
        "name": "NAS-PDU",
        "type": IEType.OCTET_STRING,
        "description": "NAS Protocol Data Unit"
    },
    43: {
        "name": "UEPagingID",
        "type": IEType.CHOICE,
        "choices": ["s-TMSI", "iMSI"],
        "description": "UE identifier for paging"
    },
    44: {
        "name": "pagingDRX",
        "type": IEType.ENUMERATED,
        "values": {"v32": 0, "v64": 1, "v128": 2, "v256": 3},
        "description": "Paging DRX cycle"
    },
    46: {
        "name": "TAIList",
        "type": IEType.SEQUENCE_OF,
        "description": "List of Tracking Area Identities"
    },
    47: {
        "name": "TAIItem", 
        "type": IEType.SEQUENCE,
        "description": "Single Tracking Area Identity"
    },
    59: {
        "name": "Global-ENB-ID",
        "type": IEType.SEQUENCE,
        "description": "Global eNB identifier"
    },
    67: {
        "name": "TAI",
        "type": IEType.SEQUENCE, 
        "description": "Tracking Area Identity"
    },
    80: {
        "name": "UEIdentityIndexValue",
        "type": IEType.BIT_STRING,
        "size": 10,
        "description": "UE identity index for paging optimization"
    },
    86: {
        "name": "E-UTRAN-Trace-ID",
        "type": IEType.OCTET_STRING,
        "size": 8,
        "description": "E-UTRAN trace identifier"
    },
    96: {
        "name": "S-TMSI",
        "type": IEType.SEQUENCE,
        "description": "SAE Temporary Mobile Subscriber Identity"
    },
    100: {
        "name": "EUTRAN-CGI",
        "type": IEType.SEQUENCE,
        "description": "E-UTRAN Cell Global Identifier"
    },
    111: {
        "name": "MessageIdentifier",
        "type": IEType.BIT_STRING,
        "size": 16,
        "description": "Warning message identifier"
    },
    112: {
        "name": "SerialNumber",
        "type": IEType.BIT_STRING, 
        "size": 16,
        "description": "Warning message serial number"
    },
    151: {
        "name": "PagingPriority",
        "type": IEType.ENUMERATED,
        "values": {"priolevel1": 0, "priolevel2": 1, "priolevel3": 2, "priolevel4": 3,
                  "priolevel5": 4, "priolevel6": 5, "priolevel7": 6, "priolevel8": 7},
        "description": "Priority level for paging"
    },
    189: {
        "name": "UserLocationInformation",
        "type": IEType.SEQUENCE,
        "description": "User location information"
    },
    227: {
        "name": "Paging-eDRXInformation", 
        "type": IEType.SEQUENCE,
        "description": "Extended DRX information for paging"
    },
    231: {
        "name": "extended-UEIdentityIndexValue",
        "type": IEType.BIT_STRING,
        "size": 14,
        "description": "Extended UE identity index value"
    },
    234: {
        "name": "NB-IoT-DefaultPagingDRX",
        "type": IEType.ENUMERATED,
        "values": {"v128": 0, "v256": 1, "v512": 2, "v1024": 3},
        "description": "NB-IoT default paging DRX"
    },
    239: {
        "name": "NB-IoT-Paging-eDRXInformation",
        "type": IEType.SEQUENCE,
        "description": "NB-IoT paging eDRX information"
    },
    244: {
        "name": "NB-IoT-UEIdentityIndexValue", 
        "type": IEType.BIT_STRING,
        "size": 12,
        "description": "NB-IoT UE identity index value"
    },
    250: {
        "name": "Coverage-Level",
        "type": IEType.INTEGER,
        "range": (0, 3),
        "description": "Coverage enhancement level"
    },
    251: {
        "name": "EnhancedCoverageRestricted",
        "type": IEType.ENUMERATED,
        "values": {"restricted": 0, "notRestricted": 1},
        "description": "Enhanced coverage restriction"
    },
    256: {
        "name": "extended-e-RAB-MaximumBitrateUL",
        "type": IEType.INTEGER,
        "range": (10001, 4000000000),
        "description": "Extended uplink maximum bitrate"
    },
    331: {
        "name": "PagingCause",
        "type": IEType.ENUMERATED, 
        "values": {"voice": 0, "sms": 1},
        "description": "Cause for paging procedure"
    },
    352: {
        "name": "Bearers-SubjectToDLDiscardingList",
        "type": IEType.SEQUENCE_OF,
        "description": "List of bearers subject to DL discarding"
    }
}

def get_ie_definition(ie_id: int) -> Optional[Dict[str, Any]]:
    """Get IE definition by ID"""
    return S1AP_IES.get(ie_id)

def get_ie_name(ie_id: int) -> str:
    """Get IE name by ID"""
    ie_def = S1AP_IES.get(ie_id)
    return ie_def["name"] if ie_def else f"Unknown-{ie_id}"
