import random, os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from vault import SecureVault, KEY_SIZE, N_KEYS
from comms import server_in, device_in, captured_messages

C1_LEN = 3
C2_LEN = 2

class Device:
    """
    Represents an IoT device participating in the vault-based mutual authentication protocol.
    If M2 or M4 tags are incorrect, or decryption/unpadding fails, the method aborts early.
    If the received r1 or r2 does not match, the method aborts and does not send ACK or update the vault.
    """
    def __init__(self, device_id:str, shared_vault: SecureVault):
        self.device_id = device_id
        self.vault     = shared_vault
        # will hold C₁, r₁, t₁, C₂, r₂ for decryption/verification
        self.stored_c1 = None
        self.stored_r1 = None
        self.stored_t1 = None
        self.stored_c2 = None
        self.stored_r2 = None

    def start(self):
        # Step 1: send M1 = (DeviceID, SessionID)
        session_id = random.randint(1, 99)
        print(f"[Device] Sending M1: (DeviceID={self.device_id}, SessionID={session_id})")
        msg1 = (self.device_id, session_id)
        captured_messages.append(msg1)
        server_in.put(msg1)

        # Step 2: receive M2 = (C₁, r₁)
        tag, c1, r1 = device_in.get()
        if tag != "M2":
            print("[Device] Expected M2; aborting.")
            return
        print(f"[Device] Received M2: (C1={c1}, r1={r1.hex()})")
        self.stored_c1 = c1
        self.stored_r1 = r1

        # derive k₁ = XOR(vault.keys at c₁)
        k1 = self.vault.derive_xor_key(c1)
        t1 = os.urandom(KEY_SIZE)
        c2 = random.sample(range(N_KEYS), C2_LEN)
        r2 = os.urandom(KEY_SIZE)
        self.stored_t1 = t1
        self.stored_c2 = c2
        self.stored_r2 = r2

        # build plaintext = r₁ || t₁ || C₂ || r₂
        c2_bytes = bytes(c2)
        plaintext = r1 + t1 + c2_bytes + r2
        cipher1   = AES.new(k1, AES.MODE_ECB)
        encrypted_M3 = cipher1.encrypt(pad(plaintext, AES.block_size))
        print(f"[Device] Sending M3: (Encrypted={encrypted_M3.hex()})")
        msg3 = ("M3", encrypted_M3)
        captured_messages.append(msg3)
        server_in.put(msg3)

        # Step 3: receive M4 = encrypted(r₂ || t₂)
        tag2, encrypted_M4 = device_in.get()
        if tag2 != "M4":
            print("[Device] Expected M4; aborting.")
            return
        print(f"[Device] Received M4: (Encrypted={encrypted_M4.hex()})")

        # decrypt with key₂⊕t₁
        k2   = self.vault.derive_xor_key(c2)
        key2 = bytes(a ^ b for (a, b) in zip(k2, t1))
        cipher2 = AES.new(key2, AES.MODE_ECB)
        plain2  = cipher2.decrypt(encrypted_M4)
        try:
            plain2 = unpad(plain2, AES.block_size)
        except ValueError:
            print("[Device] M4 padding error; aborting.")
            return

        r2_rcv = plain2[0:KEY_SIZE]
        t2     = plain2[KEY_SIZE:2*KEY_SIZE]
        if r2_rcv != r2:
            print("[Device] r2 mismatch; aborting.")
            return
        print(f"[Device] r2 matched. t2={t2.hex()}")

        # Step 4: send ACK
        # ACK is the acknowledgement message that the Device sends to the Server 
        # that means the handshake is complete
        print("[Device] Sending ACK")
        server_in.put("ACK")

        # Final: update vault with (r₁, r₂)
        self.vault.update_vault(r1, r2)
        print("[Device] Vault updated.\n")


if __name__ == "__main__":
    dev = Device("Device_01")
    dev.start()
