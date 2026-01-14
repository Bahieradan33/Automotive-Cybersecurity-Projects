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
from .security_access import (
    generate_seed, 
    derive_key_hmac_sha256, 
    constant_time_compare,
    get_security_level_config,
)
import socket
import time

# Constants for UDS services
DIAGNOSTIC_SESSION_CONTROL = 0x10
SECURITY_ACCESS = 0x27
POSITIVE_RESPONSE_OFFSET = 0x40
NEGATIVE_RESPONSE_SID = 0x7F

# ECU state
CURRENT_SESSION = 0x01  # Default session

#Negative Response Codes
NRC_SERVICE_NOT_SUPPORTED = 0x11
NRC_SUBFUNCTION_NOT_SUPPORTED = 0x12
NRC_INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT = 0x13
NRC_CONDITIONS_NOT_CORRECT = 0x22
NRC_REQUEST_SEQUENCE_ERROR = 0x24
NRC_INVALID_KEY = 0x35
NRC_EXCEEDED_NUMBER_OF_ATTEMPTS = 0x36
NRC_REQUIRED_TIME_DELAY_NOT_EXPIRED = 0x37

# Security Access related constants
HMAC_SECRET = b"SecretKey"  # Example secret for HMAC


#Lockout management
MAX_ATTEMPTS = 3
LOCKOUT_DURATION_S = 10
CLIENT_ATTEMPTS: dict[str, int] = {}
CLIENT_LOCKOUT_UNTIL: dict[str, float] = {}

# Map SecurityAccess subfunctions to (level, action)
# odd = seed request, even = key send
SUBFUNC_TO_LEVEL_ACTION: dict[int, tuple[int, str]] = {
    0x01: (1, "seed"),
    0x02: (1, "key"),
    0x03: (2, "seed"),
    0x04: (2, "key"),
}

#Store last seed issued for security access
CLIENT_LAST_SEED: dict[str, tuple[int, bytes]] = {}
CLIENT_UNLOCKED_LEVEL: dict[str, set[int]] = {}

def reset_state() -> None:
    """
    Reset ECU module state.(useful for unit testing)
    """
    global CURRENT_SESSION
    CURRENT_SESSION = 0x01  # Default session
    CLIENT_ATTEMPTS.clear()
    CLIENT_LOCKOUT_UNTIL.clear()
    CLIENT_LAST_SEED.clear()
    CLIENT_UNLOCKED_LEVEL.clear()

def build_positive_response(original_sid: int, payload: bytes = b"") -> bytes:
    """
    Build positive response service ID
    [original SID + 0x40][payload...]
    """ 
    return bytes([(original_sid + POSITIVE_RESPONSE_OFFSET) & 0xFF]) + payload  

def build_negative_response(original_sid: int, nrc: int) -> bytes:
    """
    Build negative response message
    [0x7F][original SID][NRC]
    """
    return bytes([NEGATIVE_RESPONSE_SID, original_sid & 0xFF, nrc & 0xFF])

def client_key(addr: tuple[str, int]) -> str:
    """
    Identify client by iP address only.
    Since UDP source ports chnae between programsm, so (IP,port) would break attempts tracking.
    """
    return addr[0]

def is_client_locked_out(client: str) -> bool:
    """
    Check if the client is currently locked out due to too many failed attempts.
    """                                                     
    until = CLIENT_LOCKOUT_UNTIL.get(client, 0.0)
    return time.time() < until

def handle_pdu(pdu: bytes, addr: tuple[str, int]) -> bytes:
    """
    Handle incoming UDS PDU (Protocol Data Unit) and return appropriate response PDU.
    - 0x10 (Diagnostic Session Control)
    - 0x27 (Security Access) seed request only
    """
    if len(pdu) == 0:
        return build_negative_response(0x00, NRC_INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT)

    sid = pdu[0]
    client = client_key(addr)

    # --------Diagnostic Session Control (0x10)--------
    if sid == DIAGNOSTIC_SESSION_CONTROL:
        # If message length is incorrect for known services, respond accordingly 
        if len(pdu) != 2:
            return build_negative_response(sid, NRC_INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT)

        #Accept common sub-functions: 0x01 (Default Session), 0x02 (Programming Session), 0x03 (Extended Diagnostic Session)
        requested_session = pdu[1]
        if requested_session not in (0x01, 0x02, 0x03):
            return build_negative_response(DIAGNOSTIC_SESSION_CONTROL, NRC_SUBFUNCTION_NOT_SUPPORTED)

        global CURRENT_SESSION
        CURRENT_SESSION = requested_session
    
        # Build positive response:
        return build_positive_response(DIAGNOSTIC_SESSION_CONTROL, bytes([requested_session]))
    
    # --------Security Access (0x27) Seed Request-------- 
    if sid == SECURITY_ACCESS:
        # Check for lockout
        if is_client_locked_out(client):
            return build_negative_response(SECURITY_ACCESS, NRC_REQUIRED_TIME_DELAY_NOT_EXPIRED)
        
        # Security access only allowed in Extended Diagnostic Session
        if CURRENT_SESSION != 0x03:
            return build_negative_response(SECURITY_ACCESS, NRC_CONDITIONS_NOT_CORRECT)
        
        # If message length is incorrect for known services, respond accordingly 
        if len(pdu) < 2:
            return build_negative_response(sid, NRC_INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT)
        
        sub_function = pdu[1]
        
        level_action = SUBFUNC_TO_LEVEL_ACTION.get(sub_function)
        if level_action is None:
            return build_negative_response(SECURITY_ACCESS, NRC_SUBFUNCTION_NOT_SUPPORTED)
        level, action = level_action
        config = get_security_level_config(level)
        # Seed request for selected security level
        if action == "seed":
            #Expected length: 2 bytes - [0x27][subfunction]
            if len(pdu) != 2:
                return build_negative_response(SECURITY_ACCESS, NRC_INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT) 

            # Generate and return seed
            seed = generate_seed(config.seed_length)
            CLIENT_LAST_SEED[client] = (level, seed)

            # Do not wipe previous unlock history
            CLIENT_UNLOCKED_LEVEL.setdefault(client, set())
           
            # IMPORTANT: Do NOT reset attempts or lockout on seed request
            # (otherwise attacker can bypass lockout by requesting new seeds)
            CLIENT_ATTEMPTS.setdefault(client, 0) 
            # Build positive response:
            # 0x27 + 0x40 = 0x67, payload: [sub_function][seed...]
            return build_positive_response(SECURITY_ACCESS, bytes([config.seed_subfunction]) + seed)
    

        # Seed request for selected security level
        if action == "key":
            #Expected length: 2 + key_length - [0x27][0x02][key...]
            length_required = 2 + config.key_length
            if len(pdu) != length_required:
                return build_negative_response(SECURITY_ACCESS, NRC_INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT)
            
            if client not in CLIENT_LAST_SEED:
                # No seed was issued to this client
                return build_negative_response(SECURITY_ACCESS, NRC_REQUEST_SEQUENCE_ERROR)
            
            last_level, seed = CLIENT_LAST_SEED[client]
            if last_level != level:
                # Seed was for different security level than the key attempt
                return build_negative_response(SECURITY_ACCESS, NRC_REQUEST_SEQUENCE_ERROR)
            received_key = pdu[2:2 + config.key_length]
            expected_key = derive_key_hmac_sha256(seed, HMAC_SECRET, out_length = config.key_length)

            if not constant_time_compare(received_key, expected_key):
                # Increment failed attempts
                attempts = CLIENT_ATTEMPTS.get(client, 0) + 1
                CLIENT_ATTEMPTS[client] = attempts

                if attempts >= MAX_ATTEMPTS:
                    CLIENT_LOCKOUT_UNTIL[client] = time.time() + LOCKOUT_DURATION_S
                    CLIENT_LAST_SEED.pop(client, None)  # clear stored seed
                    return build_negative_response(SECURITY_ACCESS, NRC_EXCEEDED_NUMBER_OF_ATTEMPTS)

                return build_negative_response(SECURITY_ACCESS, NRC_INVALID_KEY)

            CLIENT_UNLOCKED_LEVEL[client].add(level)
            # clean up stored seed after successful unlock
            CLIENT_LAST_SEED.pop(client, None)
            # clear failed attempts
            CLIENT_ATTEMPTS[client] = 0
            CLIENT_LOCKOUT_UNTIL.pop(client, None)
            # Build positive response:
            # 0x27 + 0x40 = 0x67, payload: [sub_function]
            return build_positive_response(SECURITY_ACCESS, bytes([config.key_subfunction]))

    # Unsupported service
    return build_negative_response(sid, NRC_SERVICE_NOT_SUPPORTED)


def main(host: str = "127.0.0.1", port: int = 13400) -> None:
       
        #Create a UDP socket(IPv4 + UDP)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        #Any UDP packet sent to this host/port will be received by the ECU simulator
        sock.bind((host, port))
        print(f"ECU Simulator listening on {host}:{port}")


        while True:
            data, addr = sock.recvfrom(4096) 
            print(f"Received message from {addr}: {data.hex()}")

            response = handle_pdu(data, addr)
            sock.sendto(response, addr)
            print(f"Sent response to {addr}: {response.hex()}")



if __name__ == "__main__":
     main()

