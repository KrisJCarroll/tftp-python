# trivialftp.py
# authored by Kristopher Carroll
# CSCE A365

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

# setting server address and outputting value set to console
SERVER_ADDRESS = args.a
print("Server address:", SERVER_ADDRESS)
# setting filename and outputting value set to console
FILENAME = args.f
print("Filename:", FILENAME)
# checking for appropriate port numbers
# *** THIS IS MUCH PRETTIER THAN USING choices=range(5000, 65535) in add_argument()!!!!!!! ***
if args.p < 5000 or args.p > 65535:
    parser.exit(message="\tERROR(args): Client port out of range\n")
CLIENT_PORT = args.p
print("Client port:", CLIENT_PORT)
# checking for appropriate server port numbers
if args.sp < 5000 or args.sp > 65535:
    parser.exit(message="\tERROR(args): Server port out of range\n")
SERVER_PORT = args.sp
print("Server port:", SERVER_PORT)

# if we made it here, it's worth making a socket 
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1) # 1 second timeout
server = (SERVER_ADDRESS, SERVER_PORT)

# setting the mode (read/write) appropriately
if args.m == 'r':
    TFTP_MODE = 'read'
elif args.m == 'w':
    TFTP_MODE = 'write'
else: # should never get here since choices=['r', 'w'] was specified for args.m but just in case...
    print("No mode provided, quitting.")
    raise SystemExit

print("Connecting to {}:{}".format(server))
s.connect((server))

TERMINATE_LENGTH = 512 + 4 # 512 bytes of data, 4 bytes header = 516 bytes maximum packet size
ENCODE_MODE = 'netascii' # we're not expected to change this

# Defining key-value pairs for ascii equivalents of opcodes
OPCODES = {
    'unknown' : 0,
    'read' : 1,
    'write' : 2,
    'data' : 3,
    'ack' : 4,
    'error' : 5
}
# Defining key-value pairs for error codes and their ascii messages
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
    Create the packet for a RRQ/WRQ as follows:
    OP   |  string  | pad | string | pad
    ------------------------------------
   |01/02| filename |  0  | mode   | 0  |
    ------------------------------------
    Requires a filename in string format and a mode representing read/write in integer format
    
    After packet has been created, send it on its way
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

# Uses the previously received packet to generate the appropriate ACK and sends it
def send_ack(packet):
    ack = bytearray(packet[0:4])
    ack[1] = 4 # change opcode to 04
    s.sendto(ack, server)

# Used to check ACKs during write operations
# Requires: previously acquired packet in bytes object
#           expected block number in integer form
# Returns: integer form of the block number ACK'ed
# Raises TypeError (generic error) if the packet is not an ACK
def check_ack(packet, block):
    # turn the requisite data into integers for easier comparison and handling
    opcode = int.from_bytes(packet[0:2], byteorder='big')
    block_num = int.from_bytes(packet[2:4], byteorder='big')
    # packet is an ACK for the expected block number
    if opcode == OPCODES['ack'] and block_num == block:
        return block
    # packet is an ACK
    elif opcode == OPCODES['ack']:
        return block_num
    # packet isn't an ACK, we shouldn't be here, break everything
    else:
        raise TypeError

"""
    Constructs data packets according to RFC1350 specifications
    Requires: Previous ACK packet received in bytes object
              Block number being written in integer form
              Data payload to be packaged in bytes object
    Sends the packet on its way after creating it.
"""
def send_data(ack, block, data):
    packet = bytearray(ack[0:2])
    packet[1] = 3 # change ACK packet to DATA packet
    # adding block number
    packet += block.to_bytes(2, byteorder='big') # padded to 2 bytes size
    # adding data
    packet += data
    s.sendto(packet, server)

# basic method for checking to see if packet is an error packet
def check_error(packet):
    data = bytearray(packet)
    opcode = data[0:2]
    return int.from_bytes(opcode, byteorder='big') == OPCODES["error"]

"""
    Core logic for read() state handling
    This method will control all the logic needed to handle a connection session
    over UDP according to RFC1350 specifications. Will respond to timeouts by
    retransmitting last ACK up to 5 times before quitting. Also gracefully exits if
    server closes connection before we expected (sometimes happens if timeout expectations
    between server and client are off significantly).

    Best part: powered exclusively by string format of filename
"""
def read(filename):
    file = open(filename, "wb")
    size = 0 # counter for total size of data received (does not include header size)
    timeouts = 0 # counter for monitoring timeouts
    block = 1 # counter for monitoring block number
    while timeouts < 5:
        try:
            packet, address = s.recvfrom(TERMINATE_LENGTH)
            size += len(packet[4:])
            # check for error packet and handle it if found
            if check_error(packet):
                errno = int.from_bytes(packet[2:4], byteorder='big')
                print("ERROR(server): ERRNO[{}] MESSAGE = {}".format(errno, TFTP_ERRORS[errno]))
                return False
            # block number is as expected, write the next data packet and send it
            if int.from_bytes(packet[2:4], byteorder='big') == block:
                timeouts = 0
                block += 1
                send_ack(packet)
                data = packet[4:] # grab the data
                file.write(data)
            # Got a packet for the wrong block number, treat it as a timeout event
            # reconstruct an ACK for the last correct data packet received
            else:
                timeouts += 1
                old_packet = bytearray(packet[0:2])
                old_packet += block.to_bytes(2, byteorder='big')
                send_ack(packet)

            if len(packet) < TERMINATE_LENGTH:
                break
        # got a timeout, resend ACK
        except socket.timeout:
            send_ack(packet)
            timeouts += 1
        except:
            print("Connection with server closed.")
            break
    # All done, clean up and let everyone know
    file.close()
    s.close()
    print("Finished reading {} from {}:{}".format(FILENAME, SERVER_ADDRESS, SERVER_PORT))
    print("\t{} bytes received.".format(size))

"""
    Core logic for write state standling
    This controls everything needed to properly handle write operations over an
    established connection with a server. Will first check to make sure the connection
    is established and acknowledged then begin a state transition that maintains
    data integrity, writing data only according to the last ACK packet received.
    This implicitly handles timeouts resulting in retransmission of ACKs
    
    Also powered entirely by string format filename
"""
def write(filename):
    file = open(filename, "rb")
    block = 0
    byte_data = file.read()
    while True:
        packet, address = s.recvfrom(TERMINATE_LENGTH)
        block = check_ack(packet, block) # get the expected block number by examining ACK
        data = byte_data[block*512 : (block*512) + 512] # get the correct data segment from block number
        block += 1 # increment the block number for next data packet
        send_data(packet, block, data)
        if len(data) < 512 or block >= 65535:
            break
    # all done, clean it up
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