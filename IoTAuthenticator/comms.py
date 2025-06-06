from queue import Queue

# “Wire” queues: Device to Server and Server to Device
server_in  = Queue()
device_in  = Queue()

# Buffer to capture every handshake message (for the attacker to replay)
captured_messages = []
