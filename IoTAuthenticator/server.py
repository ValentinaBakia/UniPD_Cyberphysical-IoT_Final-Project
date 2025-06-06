import random, os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from vault import SecureVault, KEY_SIZE, N_KEYS
from comms import server_in, device_in, captured_messages

# “Challenge lengths” from the paper (C₁ and C₂ sizes):
C1_LEN = 3
C2_LEN = 2

class Server:
    def __init__(self, shared_vault: SecureVault):
        self.vault = shared_vault
        # We’ll store nonces/t-values between steps:
        self.expecting_r1  = None
        self.expecting_c2  = None
        self.stored_t1     = None
        self.stored_r2     = None

    def start(self):
        # Step 1: wait for M1 from Device
        device_id, session_id = server_in.get()
        print(f"[Server] Received M1: (DeviceID={device_id}, SessionID={session_id})")
        if not (1 <= session_id <= 100):
            print("[Server] Invalid SessionID; aborting.")
            return

        # Step 2: generate (C₁, r₁) and send M2
        c1 = random.sample(range(N_KEYS), C1_LEN)
        r1 = os.urandom(KEY_SIZE)
        self.expecting_r1 = r1
        print(f"[Server] Sending M2: (C1={c1}, r1={r1.hex()})")
        msg2 = ("M2", c1, r1)
        captured_messages.append(msg2)  # record the exact bytes for later replay
        device_in.put(msg2)

        # Step 3: wait for M3 from Device
        tag, encrypted_M3 = server_in.get()
        if tag != "M3":
            print("[Server] Expected M3; aborting.")
            return
        print(f"[Server] Received M3: (Encrypted={encrypted_M3.hex()})")

        # Decrypt M3 under k₁ = XOR(vault.keys at indices c1)
        k1 = self.vault.derive_xor_key(c1)
        cipher1 = AES.new(k1, AES.MODE_ECB)
        plaintext = cipher1.decrypt(encrypted_M3)
        try:
            plaintext = unpad(plaintext, AES.block_size)
        except ValueError:
            print("[Server] M3 padding error; aborting.")
            return

        # parse M3 = r₁ || t₁ || C₂ || r₂
        r1_rcv = plaintext[0:KEY_SIZE]
        t1     = plaintext[KEY_SIZE : 2*KEY_SIZE]
        c2_buf = plaintext[2*KEY_SIZE : 2*KEY_SIZE + C2_LEN]
        c2     = list(c2_buf)
        r2     = plaintext[2*KEY_SIZE + C2_LEN : 3*KEY_SIZE + C2_LEN]

        if r1_rcv != r1:
            print("[Server] r1 mismatch; aborting.")
            return
        print(f"[Server] r1 matched.  Parsed t1={t1.hex()}, C2={c2}, r2={r2.hex()}")

        self.expecting_c2 = c2
        self.stored_t1    = t1
        self.stored_r2    = r2

        # Step 4: generate M4 = ENC(k₂ ⊕ t₁, r₂ || t₂)
        k2   = self.vault.derive_xor_key(c2)
        key2 = bytes(a ^ b for (a, b) in zip(k2, t1))
        t2   = os.urandom(KEY_SIZE)
        payload2 = r2 + t2
        cipher2 = AES.new(key2, AES.MODE_ECB)
        encrypted_M4 = cipher2.encrypt(pad(payload2, AES.block_size))
        print(f"[Server] Sending M4: (Encrypted={encrypted_M4.hex()})")
        msg4 = ("M4", encrypted_M4)
        captured_messages.append(msg4)
        device_in.put(msg4)

        # Step 5: wait for ACK
        ack = server_in.get()
        if ack != "ACK":
            print("[Server] Expected ACK; aborting.")
            return
        print("[Server] Received ACK.  Handshake complete.")

        # Finally: update vault with (r₁, r₂)
        self.vault.update_vault(r1, r2)
        print("[Server] Vault updated.\n")

        # Keep the server running in order to listen for the attacker
        import queue
        while True:
            extra = server_in.get()  # block until something arrives
            # Any message here must be a stale/replayed one
            print(f"[Server] Replay attack detected and rejected: {extra}")
        


if __name__ == "__main__":
    srv = Server()
    srv.start()
