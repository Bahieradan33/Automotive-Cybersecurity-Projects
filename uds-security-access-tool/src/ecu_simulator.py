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

#NRC Codes
NRC_SERVICE_NOT_SUPPORTED = 0x11
NRC_SUBFUNCTION_NOT_SUPPORTED = 0x12
NRC_INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT = 0x13


def build_positive_response(orginal_sid: int, payload: bytes) -> bytes:
    """
    Build positive response service ID
    [orginal SID + 0x40][payload...]
    """ 
    return bytes([orginal_sid + POSITIVE_RESPONSE_OFFSET]) + payload

def build_negative_response(orginal_sid: int, nrc: int) -> bytes:
    """
    Build negative response message
    [0x7F][orginal SID][NRC]
    """
    return bytes([NEGATIVE_RESPONSE, orginal_sid, nrc])




def main(host: str = 'localhost', port: int = 13400) -> None:
       
        #Create a UDP socket(IPv4 + UDP)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        #Any UDP packet sent to this host/port will be received by the ECU simulator
        sock.bind((host, port))
        print(f"ECU Simulator listening on {host}:{port}")


        while True:
            data, addr = sock.recvfrom(4096) 
            print(f"Received message from {addr}: {data.hex()}")


            response = b"Hi there!"
            sock.sendto(response, addr)
            print(f"Sent response to {addr}: {response.hex()}")



if __name__ == "__main__":
     main()

