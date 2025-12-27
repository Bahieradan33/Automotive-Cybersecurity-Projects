"""
UDS  Security Access Tool - UDS Client

Module: uds_client.py
PURPOSE:
- Send UDS PDUs over UDP to the ECU simulator
- 0x10 (Diagnostic Session Control) implementation

Notes from author:
- Transport is UDP for simplicity
- later commits add 0x27 (Security Access)
"""

from __future__ import annotations

import socket
import argparse
from dataclasses import dataclass   

# Constants for UDS services
DIAGNOSTIC_SESSION_CONTROL = 0x10
SECURITY_ACCESS = 0x27   
POSITIVE_RESPONSE_OFFSET = 0x40
NEGATIVE_RESPONSE = 0x7F

#Negative Response Codes map
NRC_map = {
    0x11: "Service Not Supported",
    0x12: "Sub-function Not Supported",
    0x13: "Incorrect Message Length or Invalid Format",
    0x21: "Request Out Of Range",
    0x22: "Conditions Not Correct",
    0x24: "Request Sequence Error",
    0x35: "Invalid Key",
    0x36: "Exceed Number Of Attempts",
    0x37: "Required Time Delay Not Expired"
}

@dataclass
class UDSResponse:
    ok: bool 
    sid: int 
    payload: bytes 
    nrc: int | None = None 

    def __str__(self) -> str:
        if self.ok:
            return f"UDSResponse(ok=True, sid=0x{self.sid:02X}, payload={self.payload.hex()})"
        nrc_name = NRC_map.get(self.nrc or 0x00, "UnknownNRC")
        return f"UDSResponse(ok=False, sid=0x{self.sid:02X}, nrc=0x{self.nrc:02X}({nrc_name}))"
    

class UDSClient:
    """
    Minimal UDS client over UDP.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 13400, timeout_s: float = 1.0) -> None:
        self.addr = (host, port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(timeout_s)

    def send_and_recv(self, pdu: bytes) -> UDSResponse:
        """
        Send a UDS PDU and wait for response.
        """
        self.sock.sendto(pdu, self.addr)
        data, _ = self.sock.recvfrom(4096)

        if len(data) < 1:
            # Malformed response
            return UDSResponse(False, 0x00, b"", nrc=0x13)

        # Negative response: [0x7F][original SID][NRC]
        if data[0] == NEGATIVE_RESPONSE:
            if len(data) != 3:
                return UDSResponse(False, 0x00, b"", nrc=0x13)
            return UDSResponse(False, sid=data[1], payload=b"", nrc=data[2])

        # Positive response: [SID+0x40][payload...]
        return UDSResponse(True, sid=data[0], payload=data[1:])

    def diagnostic_session_control(self, session_type: int) -> UDSResponse:
        """
        UDS 0x10: request diagnostic session.
        Request:  [0x10][sessionType]
        """
        pdu = bytes([DIAGNOSTIC_SESSION_CONTROL, session_type & 0xFF])
        return self.send_and_recv(pdu)

    def security_access(self, sub_function: int, key: bytes = b"") -> UDSResponse:
        """
        UDS 0x27: request security access.
        Request:  [0x27][subFunction][key...]
        """
        pdu = bytes([SECURITY_ACCESS, sub_function & 0xFF]) + key
        return self.send_and_recv(pdu)


def main() -> None:
    parser = argparse.ArgumentParser(description="UDS client (UDP demo)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=13400)
    parser.add_argument("--session", type=lambda x: int(x, 0), required=True, help="e.g. 0x03")
    args = parser.parse_args()

    client = UDSClient(args.host, args.port)
    resp = client.diagnostic_session_control(args.session)
    print(resp)


if __name__ == "__main__":
    main()