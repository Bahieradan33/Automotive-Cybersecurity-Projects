"""
UDS Security Access Tool - ECU Simulator Module

Module: ecu_simulator.py
 PURPOSE:
- provide a a local ECU simulator which responsds to a minimal subset of UDS
- Basleine commit implements only :
- 0x10 (Diagnostic Session Control) 


Notes from author:
- Transport is UDP for simplicity
- later commits add 0x27 (Security Access)

 """

from __future__ import annotations

import socket

# Constants for UDS services
DIAGNOSTIC_SESSION_CONTROL = 0x10
POSITIVE_RESPONSE_OFFSET = 0x40
NEGATIVE_RESPONSE = 0x7F

#Negative Response Codes
NRC_SERVICE_NOT_SUPPORTED = 0x11
NRC_SUBFUNCTION_NOT_SUPPORTED = 0x12
NRC_INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT = 0x13


def build_positive_response(orginal_sid: int, payload: bytes = b"") -> bytes:
    """
    Build positive response service ID
    [orginal SID + 0x40][payload...]
    """ 
    return bytes([(orginal_sid + POSITIVE_RESPONSE_OFFSET) & 0xFF]) + payload  

def build_negative_response(orginal_sid: int, nrc: int) -> bytes:
    """
    Build negative response message
    [0x7F][orginal SID][NRC]
    """
    return bytes([NEGATIVE_RESPONSE, orginal_sid & 0xFF, nrc & 0xFF])

def handle_pdu(pdu: bytes) -> bytes:
    """
    Handle incoming UDS PDU and return appropriate response PDU.
    Currently supports only Diagnostic Session Control (0x10).
    """
    if len(pdu) == 0:
        return build_negative_response(0x00, NRC_INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT)

    sid = pdu[0]

    # Handle Diagnostic Session Control (0x10)
    if sid != DIAGNOSTIC_SESSION_CONTROL:
        # For simplicity, accept any sub-function and respond positively
        return build_negative_response(sid, NRC_SERVICE_NOT_SUPPORTED)
  
    # If message length is incorrect for known services, respond accordingly 
    if len(pdu) != 2:
        return build_negative_response(sid, NRC_INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT)

    #Accept common sub-functions: 0x01 (Default Session), 0x02 (Programming Session), 0x03 (Extended Diagnostic Session)
    requested_session = pdu[1]
    if requested_session not in (0x01, 0x02, 0x03):
        return build_negative_response(DIAGNOSTIC_SESSION_CONTROL, NRC_SUBFUNCTION_NOT_SUPPORTED)
    
    # Build positive response:
    return build_positive_response(DIAGNOSTIC_SESSION_CONTROL, bytes([requested_session]))


def main(host: str = "127.0.0.1", port: int = 13400) -> None:
       
        #Create a UDP socket(IPv4 + UDP)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        #Any UDP packet sent to this host/port will be received by the ECU simulator
        sock.bind((host, port))
        print(f"ECU Simulator listening on {host}:{port}")


        while True:
            data, addr = sock.recvfrom(4096) 
            print(f"Received message from {addr}: {data.hex()}")


            response = handle_pdu(data)
            sock.sendto(response, addr)
            print(f"Sent response to {addr}: {response.hex()}")



if __name__ == "__main__":
     main()

