import threading, time
from vault import SecureVault
from server   import Server
from device   import Device
import attacker

if __name__ == "__main__":
    """
    Entry point for simulating the vault-based mutual authentication protocol
    and then execute a replay attack.

    Summary:
    1. First launch the Server and Device concurrently to perform a complete 3-message handshake:
        - M1: Device - Server
        - M2: Server - Device
        - M3: Device - Server
        - M4: Server - Device
        - ACK: Device - Server (acknowledgment)
        Both sides then update their vault keys with (r1, r2).

    2. After the honest handshake completes and the vault has rotated, invoke the Attacker.
        The Attacker replays the captured M2, M3, and M4 messages from the prior session, along
        with a bogus ACK. Because the vault keys have already changed, the Server’s decryption
        and nonce‐checks fail, demonstrating that replayed transcripts no longer work.
    """

    # Create a single, shared SecureVault instance
    shared_vault = SecureVault()
    
    # Start the Server and Device in two threads.
    srv = Server(shared_vault)
    dev = Device("Device_01", shared_vault)

    t_srv = threading.Thread(target=srv.start, daemon=True)
    t_dev = threading.Thread(target=dev.start, daemon=True)

    t_srv.start()
    t_dev.start()

    # wait for the handshake to finish
    t_dev.join()

    # Launch the replay attacker
    attacker.replay_attack()
    t_srv.join()
    
    # Sleep for a little time to process the messages
    time.sleep(0.5)
    print("Demo complete.")
