import socket

TERMINATE_LENGTH = 512

OPCODES = {
    'unknown' : 0,
    'read' : 1,
    'write' : 2,
    'data' : 3,
    'ack' : 4,
    'error' : 5
}

MODES = {
    'unknown' : 0,
    'netascii' : 1,
    'octet' : 2,
    'mail' : 3
}

udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
