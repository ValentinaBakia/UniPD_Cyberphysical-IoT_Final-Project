import time
from comms import server_in, captured_messages

def replay_attack():
    """
    Wait until the real handshake’s M2, M3, M4 have been captured in `captured_messages`,
    then resend them to the Server to show the Server rejects a stale transcript.
    """
    print("[Attacker] Waiting 1s before launching replay attack...")
    time.sleep(1.0)

    # In captured_messages, we expect:
    #   idx 0 = M1
    #   idx 1 = M2
    #   idx 2 = M3
    #   idx 3 = M4
    old_M2 = captured_messages[1]
    old_M3 = captured_messages[2]
    old_M4 = captured_messages[3]

    # Replay M2
    _, c1, r1 = old_M2
    print(f"[Attacker] Replaying M2: (C1={c1}, r1={r1.hex()})")
    server_in.put(old_M2)
    time.sleep(0.05)

    # Replay M3
    _, encrypted_M3 = old_M3
    print(f"[Attacker] Replaying M3: (Encrypted={encrypted_M3.hex()})")
    server_in.put(old_M3)
    time.sleep(0.05)

    # Replay M4
    _, encrypted_M4 = old_M4
    print(f"[Attacker] Replaying M4: (Encrypted={encrypted_M4.hex()})")
    server_in.put(old_M4)
    time.sleep(0.05)

    # Finally send a bogus ACK
    print("[Attacker] Sending bogus ACK")
    server_in.put("ACK")
    print("[Attacker] Replay attempt complete.\n")


if __name__ == "__main__":
    replay_attack()
