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
from .security_access import derive_key_hmac_sha256  

# Constants for UDS services
DIAGNOSTIC_SESSION_CONTROL = 0x10
SECURITY_ACCESS = 0x27   
POSITIVE_RESPONSE_OFFSET = 0x40
NEGATIVE_RESPONSE = 0x7F
KEY_LENGTH = 4  # bytes

#Negative Response Codes map
NRC_MAP = {
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
        nrc_name = NRC_MAP.get(self.nrc or 0x00, "UnknownNRC")
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

    def security_access_request_seed(self, level: int = 1) -> UDSResponse:
        """
        UDS 0x27: request security access.
        level 1 seed request:  [0x27][0x01]

        """ 
        #   level 1 -> 0x01
        #   level 2 -> 0x03
        #   level 3 -> 0x05
        # This is the sequence of odd numbers, so we compute: level * 2 - 1
        sub_function = (level * 2) - 1
        pdu = bytes([SECURITY_ACCESS, sub_function & 0xFF]) #+ key
        return self.send_and_recv(pdu)

    def security_access_send_key(self, level: int, key: bytes) -> UDSResponse:
        """
        UDS 0x27: send security access key.
        level 1 send key:  [0x27][0x02][key...]
        """ 
        if not key or len(key) != KEY_LENGTH:
            raise ValueError(f"Key must be {KEY_LENGTH} bytes")
        #   level 1 -> 0x02
        #   level 2 -> 0x04 
        #   level 3 -> 0x06
        # This is the sequence of even numbers, so we compute: level * 2
        sub_function = (level * 2) 
        pdu = bytes([SECURITY_ACCESS, sub_function & 0xFF]) + key
        return self.send_and_recv(pdu)

    def security_access_unlock_lvl1(self, secret: bytes) -> tuple[UDSResponse, UDSResponse]:
        """
        Full unlcock sequence for security level 1:
        1. Request seed
        2. Derive key using HMAC-SHA256
        3. Send key
        Return both responses (seed response, key response)
        """
        seed_resp = self.security_access_request_seed(level=1)
        if (not seed_resp.ok) or (len(seed_resp.payload) < 1 + KEY_LENGTH):
            return seed_resp  # return error response

        sub_function = seed_resp.payload[0]
        seed = seed_resp.payload[1:]  # first byte is sub_function
        derived_key = derive_key_hmac_sha256(seed, secret, out_length=KEY_LENGTH)
        key_resp = self.security_access_send_key(level=1, key=derived_key)
        return seed_resp, key_resp

def main() -> None:
    parser = argparse.ArgumentParser(description="UDS client (UDP demo)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=13400)
    parser.add_argument("--secret", default="HMAC_SECRET", help="Secret key for HMAC-SHA256")

    service_group = parser.add_mutually_exclusive_group(required=True)
    service_group.add_argument("--session", type=lambda x: int(x, 0), help="e.g. 0x03")
    service_group.add_argument("--seed", action="store_true", help="Request security access seed")
    service_group.add_argument("--unlock", action="store_true", help="Do seed request + key send for 27 01 and 27 02")    
    args = parser.parse_args()

    client = UDSClient(args.host, args.port)
    secret_bytes = args.secret.encode("utf-8")

    if args.seed:
        resp = client.security_access_request_seed(level=1)
        print(resp)

        if resp.ok and len(resp.payload) >= 1:
            sub_function = resp.payload[0]
            seed = resp.payload[1:]
            print(f"Seed sub_function: 0x{sub_function:02X}, seed: {seed.hex()}")
        return
    
    if args.unlock:
        
        seed_resp, key_resp = client.security_access_unlock_lvl1(secret_bytes)
        print("Seed Response:", seed_resp)
        print("Key Response:", key_resp)

        if key_resp.ok:
            print("Security Level 1 unlocked successfully.")
        else:
            print("Failed to unlock Security Level 1.")
        return
    
    
    resp = client.diagnostic_session_control(args.session)
    print(resp)

    if resp.ok and len(resp.payload) >= 1:
        session = resp.payload[0]
        print(f"Session switched to 0x{session:02X}")

if __name__ == "__main__":
    main()