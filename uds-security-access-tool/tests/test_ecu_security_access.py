"""
Docstring for uds-security-access-tool.tests.test_ecu_security_access
Unit tests for ECU security access handling.
"""

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

    cfg1 =ecu.get_security_level_config(1)
    assert len(seed) == cfg1.seed_length
    # Compute expected key and send: 27 02 <key> -> 67 02
    key = derive_key_hmac_sha256(seed, ecu.HMAC_SECRET, out_length=cfg1.key_length)
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

    cfg1 = ecu.get_security_level_config(1)
    wrong_key = b"\x00" * cfg1.key_length

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



def test_security_access_level2_seed_then_key_success() -> None:
    ecu.reset_state()
    addr = ("127.0.0.1", 50000)

    # Extended session first
    resp = ecu.handle_pdu(bytes([ecu.DIAGNOSTIC_SESSION_CONTROL, 0x03]), addr)
    assert resp == bytes([0x50, 0x03])

    cfg2 = ecu.get_security_level_config(2)

    # Request level 2 seed: 27 03 -> 67 03 <seed>
    seed_resp = ecu.handle_pdu(bytes([ecu.SECURITY_ACCESS, cfg2.seed_subfunction]), addr)
    assert seed_resp[0] == 0x67
    assert seed_resp[1] == cfg2.seed_subfunction

    seed = seed_resp[2:]
    assert len(seed) == cfg2.seed_length

    # Send level 2 key: 27 04 <key> -> 67 04
    key = derive_key_hmac_sha256(seed, ecu.HMAC_SECRET, out_length=cfg2.key_length)
    key_resp = ecu.handle_pdu(bytes([ecu.SECURITY_ACCESS, cfg2.key_subfunction]) + key, addr)
    assert key_resp == bytes([0x67, cfg2.key_subfunction])


def test_security_access_level_mismatch_seed_then_wrong_level_key_returns_sequence_error() -> None:
    ecu.reset_state()
    addr = ("127.0.0.1", 50000)

    # Extended session first
    ecu.handle_pdu(bytes([ecu.DIAGNOSTIC_SESSION_CONTROL, 0x03]), addr)

    cfg1 = ecu.get_security_level_config(1)
    cfg2 = ecu.get_security_level_config(2)

    # Request level 1 seed
    seed_resp = ecu.handle_pdu(bytes([ecu.SECURITY_ACCESS, cfg1.seed_subfunction]), addr)
    seed = seed_resp[2:]
    assert len(seed) == cfg1.seed_length

    # Try to send a level 2 key using the level 1 seed -> should be RequestSequenceError (0x24)
    wrong_level_key = derive_key_hmac_sha256(seed, ecu.HMAC_SECRET, out_length=cfg2.key_length)

    resp = ecu.handle_pdu(bytes([ecu.SECURITY_ACCESS, cfg2.key_subfunction]) + wrong_level_key, addr)
    assert resp[0] == ecu.NEGATIVE_RESPONSE_SID
    assert resp[2] == ecu.NRC_REQUEST_SEQUENCE_ERROR


def test_level2_lockout_after_three_invalid_keys_then_delay_nrc() -> None:
    ecu.reset_state()

    # Extended session first
    ecu.handle_pdu(bytes([ecu.DIAGNOSTIC_SESSION_CONTROL, 0x03]), ("127.0.0.1", 50000))

    ip = "127.0.0.1"
    cfg2 = ecu.get_security_level_config(2)

    # Get one level 2 seed
    seed_resp = ecu.handle_pdu(bytes([ecu.SECURITY_ACCESS, cfg2.seed_subfunction]), (ip, 50001))
    assert seed_resp[0] == 0x67

    wrong_key = b"\x00" * cfg2.key_length

    # Send wrong key 3 times, varying port (simulates new process ports)
    r1 = ecu.handle_pdu(bytes([ecu.SECURITY_ACCESS, cfg2.key_subfunction]) + wrong_key, (ip, 51001))
    r2 = ecu.handle_pdu(bytes([ecu.SECURITY_ACCESS, cfg2.key_subfunction]) + wrong_key, (ip, 51002))
    r3 = ecu.handle_pdu(bytes([ecu.SECURITY_ACCESS, cfg2.key_subfunction]) + wrong_key, (ip, 51003))

    assert r1[0] == 0x7F and r1[2] == ecu.NRC_INVALID_KEY
    assert r2[0] == 0x7F and r2[2] == ecu.NRC_INVALID_KEY
    assert r3[0] == 0x7F and r3[2] == ecu.NRC_EXCEEDED_NUMBER_OF_ATTEMPTS

    # Immediately request seed -> NRC 0x37
    locked_seed = ecu.handle_pdu(bytes([ecu.SECURITY_ACCESS, cfg2.seed_subfunction]), (ip, 52000))
    assert locked_seed[0] == 0x7F
    assert locked_seed[2] == ecu.NRC_REQUIRED_TIME_DELAY_NOT_EXPIRED
