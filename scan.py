import ipaddress
import select
import socket
import sys

#
# Settings
#
timeout_seconds = 0.5 # Can increase this if not finding anything, larger is longer scan
data = [0x0, 0x1, 0x0, 0x0, 0x0, 0x6, 0x0, 0x3, 0x9c, 0x40, 0x0, 0x45]
device_id_index = 6
max_device_id = 32 # 247 for full scan
retries = 3

#
# Validate command line
#
arg_len = len(sys.argv)
if arg_len < 2 or arg_len > 3 :
    print("Usage: python scan.py <IP Address> [<port>]")
    sys.exit(1)

HOST = ''
PORT = 1502

# Parse IP Address
try:
    HOST = format(ipaddress.ip_address(sys.argv[1]))
except ValueError as e:
    print("Invalid IP Address {}".format(e))
    sys.exit(1)
    
if (arg_len > 2):
    # Parse port
    try:
        PORT = int(sys.argv[2])
        if (PORT < 1024) or (PORT > 49151):
            print("Port should be between 1024 and 49151")
        sys.exit(1)
    except ValueError as e:
        print("Invalid Port {}".format(e))
        sys.exit(1)

#
# Perform scan
#
device_id = 1
while (device_id <= max_device_id):
    # Update device_id
    data[device_id_index] = device_id
    attempt = 1

    while (attempt <= retries ):
        try:
            # Create a socket (SOCK_STREAM means a TCP socket)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                # Connect to server and send data
                sock.connect((HOST, PORT))
                sock.setblocking(0)
                sock.sendall(bytes(data))
                print("Scanning ID: {} ... ". format(device_id), end='')

                # Receive data from the server and shut down
                ready = select.select([sock], [], [], timeout_seconds)
                
                if ready[0]:
                    received = sock.recv(1024)
                    
                    print("Received: {}".format(received))
                else:
                    print("Timedout")
                break
            
        except ConnectionResetError as e:
            print()
            print("Connection reset {}".format(e))
            attempt = attempt + 1
    
    if (attempt > retries):
        print("Aborting due to multiple attempts")
        break
    
    device_id = device_id + 1
            