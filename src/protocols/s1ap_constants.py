"""
S1AP Protocol Constants and Definitions
Based on 3GPP TS 36.413 specification
"""

from typing import Dict, Any

# S1AP Message Types
S1AP_MESSAGE_TYPES = {
    0x00: "InitiatingMessage",
    0x20: "SuccessfulOutcome", 
    0x40: "UnsuccessfulOutcome"
}

# S1AP Procedure Codes (3GPP TS 36.413 V18.3.0)
S1AP_PROCEDURES = {
    0: "HandoverPreparation",
    1: "HandoverResourceAllocation",
    2: "HandoverNotification", 
    3: "PathSwitchRequest",
    4: "HandoverCancel",
    5: "E-RABSetup",
    6: "E-RABModify",
    7: "E-RABRelease",
    8: "E-RABReleaseIndication",
    9: "InitialContextSetup",
    10: "Paging",
    11: "downlinkNASTransport",
    12: "initialUEMessage",
    13: "uplinkNASTransport",
    14: "Reset",
    15: "ErrorIndication",
    16: "NASNonDeliveryIndication",
    17: "S1Setup",
    18: "UEContextReleaseRequest",
    19: "DownlinkS1cdma2000tunnelling",
    20: "UplinkS1cdma2000tunnelling",
    21: "UEContextModification",
    22: "UECapabilityInfoIndication",
    23: "UEContextRelease",
    24: "eNBStatusTransfer",
    25: "MMEStatusTransfer",
    26: "DeactivateTrace",
    27: "TraceStart",
    28: "TraceFailureIndication",
    29: "ENBConfigurationUpdate",
    30: "MMEConfigurationUpdate",
    31: "LocationReportingControl",
    32: "LocationReportingFailureIndication",
    33: "LocationReport",
    34: "OverloadStart",
    35: "OverloadStop",
    36: "WriteReplaceWarning",
    37: "eNBDirectInformationTransfer",
    38: "MMEDirectInformationTransfer",
    39: "PrivateMessage",
    40: "eNBConfigurationTransfer",
    41: "MMEConfigurationTransfer",
    42: "CellTrafficTrace",
    43: "Kill",
    44: "downlinkUEAssociatedLPPaTransport",
    45: "uplinkUEAssociatedLPPaTransport",
    46: "downlinkNonUEAssociatedLPPaTransport",
    47: "uplinkNonUEAssociatedLPPaTransport",
    48: "UERadioCapabilityMatch",
    49: "PWSRestartIndication",
    50: "E-RABModificationIndication",
    51: "PWSFailureIndication",
    52: "RerouteNASRequest",
    53: "UEContextModificationIndication",
    54: "ConnectionEstablishmentIndication",
    55: "UEContextSuspend",
    56: "UEContextResume",
    57: "NASDeliveryIndication",
    58: "RetrieveUEInformation",
    59: "UEInformationTransfer",
    60: "eNBCPRelocationIndication",
    61: "MMECPRelocationIndication",
    62: "SecondaryRATDataUsageReport",
    63: "UERadioCapabilityIDMapping",
    64: "HandoverSuccess",
    65: "eNBEarlyStatusTransfer",
    66: "MMEEarlyStatusTransfer"
}

# Criticality Values
S1AP_CRITICALITY = {
    0x00: "reject",
    0x40: "ignore", 
    0x80: "notify"
}

# PPID (Payload Protocol Identifier) for S1AP
S1AP_PPID = 18

# SCTP Port for S1AP
S1AP_PORT = 36412
