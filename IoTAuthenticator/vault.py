import os, hmac, hashlib

# Set the parameters
KEY_SIZE = 16   # each key is 16 bytes (128 bits)
N_KEYS   = 5    # number of vault keys

class SecureVault:
    """
     Class that manages a collection of cryptographic keys and provides methods to:
      - Derive a composite key by doing XOR to a selected subset of vault keys.
      - Update all vault keys atomically using the HMAC of session nonces.
    """
    def __init__(self):
        self.keys = [os.urandom(KEY_SIZE) for _ in range(N_KEYS)]

    def derive_xor_key(self, indices):
        # Start with the first selected key
        k = bytearray(self.keys[indices[0]])
        # and do XOR for the rest keys
        for idx in indices[1:]:
            for i in range(KEY_SIZE):
                k[i] ^= self.keys[idx][i]
        return bytes(k)

    def update_vault(self, r1, r2):
        # Compute HMAC-SHA256 over (r1,r2)
        allkeys = b''.join(self.keys)
        digest = hmac.new(r1 + r2, allkeys, hashlib.sha256).digest()

        # We need N_KEYS partitions of KEY_SIZE bytes.  SHA256 is 32 bytes, but N_KEYS×KEY_SIZE = 80 bytes.
        # So we “stretch” by hashing again if needed.
        combined = digest
        while len(combined) < N_KEYS * KEY_SIZE:
            combined += hmac.new(combined, combined, hashlib.sha256).digest()

        partitions = [
            combined[i*KEY_SIZE : (i+1)*KEY_SIZE]
            for i in range(N_KEYS)
        ]

        # XOR each vault.key with its corresponding partition
        for i in range(N_KEYS):
            newkey = bytearray(self.keys[i])
            part   = partitions[i]
            for j in range(KEY_SIZE):
                newkey[j] ^= part[j]
            self.keys[i] = bytes(newkey)
