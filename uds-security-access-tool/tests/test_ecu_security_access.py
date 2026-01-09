import time
import src.ecu_simulator as ecu
from src.security_access import derive_key_hmac_sha256

def _sid(resp: bytes) -> int:
    return resp[0]

def _nrc(resp: bytes) -> int:
    # Negative response: 7F <sid> <nrc>
    return resp[2]

def test_security_access_blocked_in_default_session() -> None:
    ecu.reset_state()
    addr = ("127.0.0.1", 50000)
    resp = ecu.handle_pdu(bytes([ecu.SECURITY_ACCESS, 0x01]), addr)
    assert _sid(resp) == ecu.NEGATIVE_RESPONSE_SID
    assert _nrc(resp) == ecu.NRC_CONDITIONS_NOT_CORRECT

def test_security_access_seed_then_key_success_in_extended_session() -> None:
    ecu.reset_state()
    addr = ("127.0.0.1", 50000)

    # Switch to extended session: 10 03 -> 50 03
    resp = ecu.handle_pdu(bytes([ecu.DIAGNOSTIC_SESSION_CONTROL, 0x03]), addr)
    assert resp == bytes([0x50, 0x03])

    # Request seed: 27 01 -> 67 01 <seed>
    seed_resp = ecu.handle_pdu(bytes([ecu.SECURITY_ACCESS, 0x01]), addr)
    assert seed_resp[0] == 0x67
    assert seed_resp[1] == 0x01
    seed = seed_resp[2:]
    assert len(seed) == ecu.SEED_LENGTH

    # Compute expected key and send: 27 02 <key> -> 67 02
    key = derive_key_hmac_sha256(seed, ecu.HMAC_SECRET, out_length=ecu.KEY_LENGTH)
    key_resp = ecu.handle_pdu(bytes([ecu.SECURITY_ACCESS, 0x02]) + key, addr)
    assert key_resp == bytes([0x67, 0x02])

def test_lockout_after_three_invalid_keys_then_delay_nrc() -> None:
    ecu.reset_state()

    # Extended session first
    ecu.handle_pdu(bytes([ecu.DIAGNOSTIC_SESSION_CONTROL, 0x03]), ("127.0.0.1", 50000))

    ip = "127.0.0.1"

    # Get one seed
    seed_resp = ecu.handle_pdu(bytes([ecu.SECURITY_ACCESS, 0x01]), (ip, 50001))
    seed = seed_resp[2:]

    wrong_key = b"\x00" * ecu.KEY_LENGTH

    # Send wrong key 3 times, varying port (simulates new process ports)
    r1 = ecu.handle_pdu(bytes([ecu.SECURITY_ACCESS, 0x02]) + wrong_key, (ip, 51001))
    r2 = ecu.handle_pdu(bytes([ecu.SECURITY_ACCESS, 0x02]) + wrong_key, (ip, 51002))
    r3 = ecu.handle_pdu(bytes([ecu.SECURITY_ACCESS, 0x02]) + wrong_key, (ip, 51003))

    assert r1[0] == 0x7F and r1[2] == ecu.NRC_INVALID_KEY
    assert r2[0] == 0x7F and r2[2] == ecu.NRC_INVALID_KEY
    assert r3[0] == 0x7F and r3[2] == ecu.NRC_EXCEEDED_NUMBER_OF_ATTEMPTS

    # Immediately request seed -> NRC 0x37
    locked_seed = ecu.handle_pdu(bytes([ecu.SECURITY_ACCESS, 0x01]), (ip, 52000))
    assert locked_seed[0] == 0x7F
    assert locked_seed[2] == ecu.NRC_REQUIRED_TIME_DELAY_NOT_EXPIRED
