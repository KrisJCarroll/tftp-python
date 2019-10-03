import socket
import argparse

# Parsing for argument flags
parser = argparse.ArgumentParser()
parser.add_argument("-a", help="supply a destination address")
parser.add_argument("-f", help="supply a filename in string format")
parser.add_argument("-p", type=int, help="supply client port information")
parser.add_argument("-sp", type=int, help="supply server port information")
parser.add_argument("-m", choices=['r', 'w'], help="choose either (r)ead or (w)rite mode")

args = parser.parse_args()

SERVER_ADDRESS = args.a
print("Server address:", SERVER_ADDRESS)
FILENAME = args.f
print("Filename:", FILENAME)
if args.p < 5000 or args.p > 65535:
    parser.exit(message="\tERROR(args): Client port out of range\n")
CLIENT_PORT = args.p
print("Client port:", CLIENT_PORT)
if args.sp < 5000 or args.sp > 65535:
    parser.exit(message="\tERROR(args): Server port out of range\n")
SERVER_PORT = args.sp
print("Server port:", SERVER_PORT)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1) # 2 second timeout
server = (SERVER_ADDRESS, SERVER_PORT)

if args.m == 'r':
    TFTP_MODE = 'read'
elif args.m == 'w':
    TFTP_MODE = 'write'
else:
    print("No mode provided, quitting.")
    raise SystemExit

print("Connecting to {}:{}".format(SERVER_ADDRESS, SERVER_PORT))
s.connect((SERVER_ADDRESS, SERVER_PORT))

TERMINATE_LENGTH = 512 + 4 # 512 bytes of data, 4 bytes header
ENCODE_MODE = 'netascii'

OPCODES = {
    'unknown' : 0,
    'read' : 1,
    'write' : 2,
    'data' : 3,
    'ack' : 4,
    'error' : 5
}

TFTP_ERRORS = {
    0 : "Undefined error.",
    1 : "File not found.",
    2 : "Access violation.",
    3 : "Disk full or allocation exceeded.",
    4 : "Illegal TFTP operation.",
    5 : "Unknown TID.",
    6 : "File already exists.",
    7 : "No such user.",
}

""" 
    Create the packet for a RRQ as follows:
    OP   |  string  | pad | string | pad
    ------------------------------------
   |01/02| filename |  0  | mode   | 0  |
    ------------------------------------
"""
def send_request(filename, mode):
    request = bytearray()
    # Append opcode for read request
    request.append(0)
    request.append(OPCODES[mode])

    # Append encoded filename
    request = request + bytearray(filename.encode('ascii'))

    # padding
    request.append(0)

    # Append encoded mode
    request = request + bytearray(ENCODE_MODE.encode('ascii'))

    # padding
    request.append(0)

    requested = s.sendto(request, server)

def send_ack(packet):
    ack = bytearray(packet[0:4])
    ack[1] = 4 # change opcode to 04
    s.sendto(ack, server)

def check_ack(packet, block):
    opcode = int.from_bytes(packet[0:2], byteorder='big')
    block_num = int.from_bytes(packet[2:4], byteorder='big')
    if opcode == OPCODES['ack'] and block_num == block:
        return block_num
    elif opcode == OPCODES['ack']:
        return block_num
    else:
        raise TypeError

def send_data(ack, block, data):
    packet = bytearray(ack[0:2])
    packet[1] = 3
    # adding block number
    packet += block.to_bytes(2, byteorder='big')
    # adding data
    packet += data
    s.sendto(packet, server)

def check_error(packet):
    data = bytearray(packet)
    opcode = data[0:2]
    return int.from_bytes(opcode, byteorder='big') == OPCODES["error"]

def read(filename):
    file = open(filename, "wb")
    size = 0
    timeouts = 0
    block = 1
    while timeouts < 2:
        try:
            packet, address = s.recvfrom(TERMINATE_LENGTH)
            size += len(packet[4:])
            if check_error(packet):
                errno = int.from_bytes(packet[2:4], byteorder='big')
                print("ERROR(server): ERRNO[{}] MESSAGE = {}".format(errno, TFTP_ERRORS[errno]))
                return False
            if int.from_bytes(packet[2:4], byteorder='big') == block:
                timeouts = 0
                block += 1
                send_ack(packet)
                data = packet[4:] # grab the data
                file.write(data)
            else:
                timeouts += 1
                old_packet = bytearray(packet[0:2])
                old_packet += block.to_bytes(2, byteorder='big')
                send_ack(packet)

            if len(packet) < TERMINATE_LENGTH:
                break
        except socket.timeout:
            send_ack(packet)
            timeouts += 1
    # All done, clean up and let everyone know
    file.close()
    s.close()
    print("Finished reading {} from {}:{}".format(FILENAME, SERVER_ADDRESS, SERVER_PORT))
    print("\t{} bytes received.".format(size))

def write(filename):
    file = open(filename, "rb")
    block = 0
    byte_data = file.read()
    while True:
        packet, address = s.recvfrom(TERMINATE_LENGTH)
        block = check_ack(packet, block)
        data = byte_data[block*512 : (block*512) + 512]
        block += 1
        send_data(packet, block, data)
        if len(data) < 512 or block >= 65535:
            break
    print("Finished writing {} to {}:{}".format(FILENAME, SERVER_ADDRESS, SERVER_PORT))
    file.close()
    s.close()
            

            

def main():
    print("Sending {} request...".format(TFTP_MODE))
    send_request(FILENAME, TFTP_MODE)

    if TFTP_MODE == 'read':
        read(FILENAME)
    
    elif TFTP_MODE == 'write':
        write(FILENAME)

if __name__ == '__main__':
    main()