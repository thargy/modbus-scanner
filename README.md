# Modbus Scanner

This is a prototype repository to attempt to create a fast scan of the modbus for devices, in python.

## Usage

```bash
py scan.py <Modbus Server IP Address> [<port>]

# for help
py scan.py -h

# e.g. scans server at 192.0.0.10 checking all device IDs.
py scan.py 192.0.0.10

# e.g. scans server at 192.0.0.10 looking for 2 inverters.
py scan.py 192.0.0.10 2

# e.g. scans ids 1,5,6,7,8,9 using server at 192.0.0.10, and dump first 20 bytes of response
py scan.py 192.0.0.10 -d 1,5,6-9 -x 20

```

The port number defaults to `1502`.
