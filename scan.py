from ipaddress import ip_address
import select
from time import sleep as sleep
import socket
import sys
import argparse
from colorama import init as colorama_init
from colorama import Fore
from colorama import Style


def port(value):
    '''The function `port` takes a value as input and returns it as an integer if it is between 1024 and
    49151, otherwise it raises an error.

    Parameters
    ----------
    value
        The `value` parameter is the input value that is being checked to see if it is a valid port number.

    Returns
    -------
        the port number as an integer.

    '''
    p = int(value)
    if p < 1024 or p > 49151:
        raise argparse.ArgumentTypeError(
            f"{value} must be between 1024 and 49151")
    return p


def retries(value):
    '''The function `retries` takes a value as input and returns it as an integer if it is between 0 and
    10, otherwise it raises an error.

    Parameters
    ----------
    value
        The `value` parameter is the input value that needs to be converted to an integer and checked if it
    falls within the range of 0 to 10.

    Returns
    -------
        the integer value of the input parameter after validating that it is between 0 and 10.

    '''
    r = int(value)
    if r < 0 or r > 10:
        raise argparse.ArgumentTypeError(f"{value} must be between 0 and 10")
    return r


def timeout(value):
    '''The `timeout` function takes a value and returns it as a float if it is between 0.0 and 60.0
    seconds, otherwise it raises an error.

    Parameters
    ----------
    value
        The value parameter represents the input value that is being checked for validity. In this case, it
    is expected to be a string representing a floating-point number.

    Returns
    -------
        a float representing the timeout value.

    '''
    t = float(value)
    if t < 0.0 or t > 60.0:
        raise argparse.ArgumentTypeError(
            f"{value} must be between 0.0 and 60.0 seconds")
    return t


def device_id(value):
    '''The `device_id` function takes a value and checks if it is a valid device ID between 1 and 247,
    raising an error if it is not.

    Parameters
    ----------
    value
        The value parameter is the input value that is being checked for validity as a device ID.

    Returns
    -------
        the device ID as an integer.

    '''
    id = int(value)
    if (id < 1) or id > 247:
        raise argparse.ArgumentTypeError(
            f"'{value}' must be a device ID between 1 and 247")
    return id


def deviceIds(value):
    '''The function `device_ids` takes a string input and returns a list of device IDs, where the input can
    be a single ID or a range of IDs separated by commas.

    Parameters
    ----------
    value
        The `value` parameter is a string that represents a list of device IDs. The device IDs can be
    specified as individual IDs or as ranges separated by a hyphen. For example, the string "1,3-5,7"
    represents the device IDs 1, 3, 4, 5 and 7

    Returns
    -------
        The function `device_ids` returns a list of device IDs.

    '''
    parts = [p.strip() for p in value.split(',')]
    ids = []
    for p in parts:
        r = [i.strip() for i in p.split('-')]
        l = len(r)
        if l < 2:
            # We have a single id
            ids.append(device_id(r[0]))

        elif l > 2:
            # Invalid range, multiple '-'s
            raise argparse.ArgumentTypeError(
                f"'{p}' in '{value}' looks like a range but has multiple '-'s.")

        else:
            # Looks like a range
            start = device_id(r[0])
            end = device_id(r[1])
            if (end < start):
                raise argparse.ArgumentTypeError(
                    f"'{start}' must be less than or equal to {end}.")

            ids.extend(range(start, end+1))

    return sorted(set(ids))

def isInverter(request, response):
    '''The function `isInverter` checks if the `response` represents an inverter.
    
    Parameters
    ----------
    request
        The `request` parameter is a list of bytes that represents the TCP request. It includes the transcation ID
        and the device ID.
    response
        The response parameter is a list of bytes that represents the response received.
    
    Returns
    -------
        a boolean value indicating whether the response represents an inverter.
    
    '''
    # This is a simplified check using only the first 9 registers
    # requesting the full 69 registers can actually result in a split response on occassion. 
    expected = [request[0], request[1],
               0x00, 0x00, 0x00, 0x15, 
               request[6],
               0x03, 0x12, 0x53, 0x75, 0x6e, 0x53, 0x00, 0x01, 0x00, 0x41, 0x53, 0x6f, 0x6c, 0x61, 0x72, 0x45, 0x64, 0x67, 0x65, 0x20]
    return list(response) == expected


# Support console colors
colorama_init()

# Parse command line
parser = argparse.ArgumentParser(
    description='Performs a scan of TCP Modbus looking for device IDs.')

parser.add_argument('ipAddress', type=ip_address,
                    help="The Modbus server to query.")
parser.add_argument('count', type=int, nargs='?',
                    help="The number of inverters to find. Use <=0 to scan fully. Defaults to -1", default=-1)
parser.add_argument('--version', action='version', version='%(prog)s 0.1')
parser.add_argument('-d', '--deviceIds', type=deviceIds, metavar="N", required=False,
                    help='The device ids to scan, can be comma-separated integers, or hypenated range, e.g. 1,2,4-7,10. Default is 1-247.', default="1-247")
parser.add_argument('-p', '--port', type=port, required=False,
                    metavar="P", help='The port number (1024-49151) of TCP Modbus. Default is 1502.', default=1502)
parser.add_argument('-t', '--timeout', type=timeout, required=False,
                    metavar="T", help='The timeout in seconds. Default is 3.0.', default=3.0)
parser.add_argument('-r', '--retries', type=retries, metavar="N", required=False,
                    help='The number of retries on a communication failure. Default is 3.', default=3)
parser.add_argument('-x', '--maxHex', type=int, metavar="N", required=False,
                    help='The maximum length of response hex dump. Use <= 0 to not dump response. Default is -1.', default=-1)

args = parser.parse_args()

HOST = str(args.ipAddress)
COUNT = args.count
PORT = args.port
TIMEOUT = args.timeout
RETRIES = args.retries
IDS = args.deviceIds
MAXHEX = args.maxHex

#
# Settings
#
transaction = 0
request = [0x0, 0x0, 0x0, 0x0, 0x0, 0x6, 0x0, 0x3, 0x9c, 0x40, 0x0, 0x09]
device_id_index = 6
connected = False
inverters = 0

#
# Perform scan
#
for device_id in IDS:
    # Update transaction count
    transaction = transaction + 1
    
    # Update request
    request[0] = int(transaction / 256)
    request[1] = transaction % 256
    request[device_id_index] = device_id
        
    attempt = 1
    while not connected and attempt <= RETRIES:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            # Connect to
            print(f"Connecting to {HOST}:{PORT} ... ", end= "")
            sock.settimeout(TIMEOUT)
            sock.connect((HOST, PORT))
            connected = True  
            print(f"{Fore.GREEN}SUCCEEDED{Fore.RESET}")
        except socket.error as e:            
            print(f"{Fore.RED}FAILED{Fore.RESET} {e}")
            connected = False
            attempt = attempt + 1
            sleep(1.0)  

    if (attempt > RETRIES):
        print(f"{Fore.RED}Aborting due to {attempt-1} connection attempt failures! {Fore.RESET}")
        sys.exit(1)
    
    while (attempt <= RETRIES):
        try:
            # Create a socket (SOCK_STREAM means a TCP socket)
                sock.setblocking(0)
                sock.sendall(bytes(request))
                print("Scanning ID: {} ...". format(device_id), end='')

                # Receive data from the server and shut down
                ready = select.select([sock], [], [], TIMEOUT)

                if ready[0]:
                    response = sock.recv(1024)
                    
                    if (isInverter(request, response)):
                        print(f" {Fore.GREEN}INVERTER{Fore.RESET}", end='')
                        inverters=inverters+1
                    else:
                        print(f" {Fore.YELLOW}Unknown Device{Fore.RESET}", end='')

                    print(f" Received ({len(response)} bytes)", end='')
                    
                    if (MAXHEX > 0):
                        print(f": { ' '.join(format(x, '02x') for x in response[:MAXHEX]) }{'...' if len(response) > MAXHEX else ''}")
                    else:
                        print()
                        
                else:
                    print(f" {Fore.RED}Timedout{Fore.RESET}")
                break

        except socket.error as e:
            print()
            print(f" {Fore.RED}FAILED{Fore.RESET}: {e}")
            attempt = attempt + 1
            
    if (COUNT > 0 and inverters >= COUNT):
        print(f"{Fore.GREEN}Found all {inverters} inverters! {Fore.RESET}")
        break

    if (attempt > RETRIES):
        print(f"{Fore.RED}Aborting scanning device ID {device_id} after {attempt-1} attempts! {Fore.RESET}")
        break
    
# Sanity check
if (connected):
    try:
        # Connect to
        print(f"Closing connection ... ", end= "")
        sock.close()
        print(f"{Fore.GREEN}SUCCEEDED{Fore.RESET}")
    except socket.error as e:            
        print(f"{Fore.RED}FAILED{Fore.RESET} {e}")
    finally:
        connected = False

print()
print("DONE!")
