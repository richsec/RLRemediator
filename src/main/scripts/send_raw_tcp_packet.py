import socket
import sys
from struct import *

SRC_IP = '192.168.1.130'
SRC_PORT = 9999
DST_IP = '54.208.220.41'
DST_PORT = 443


# checksum functions needed for calculation checksum
def checksum(msg):
    s = 0
    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i + 1]) << 8)
        s = s + w
    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    # complement and mask to 4 byte short
    s = ~s & 0xffff
    return s

source_ip = '192.168.1.130'
dest_ip = '54.208.220.41'

# create a raw socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
except socket.error, msg:
    print 'Socket could not be created. Error Code : '\
        + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()

# tcp header fields
tcp_source = SRC_PORT   # source port
tcp_dest = DST_PORT     # destination port
tcp_seq = 454
tcp_ack_seq = 0
tcp_doff = 5    # 4 bit field, size of tcp header, 5 * 4 = 20 bytes
# tcp flags
tcp_fin = 0
tcp_syn = 1
tcp_rst = 0
tcp_psh = 0
tcp_ack = 0
tcp_urg = 0
tcp_window = socket.htons(5840)    # maximum allowed window size
tcp_check = 0
tcp_urg_ptr = 0

tcp_offset_res = (tcp_doff << 4) + 0
tcp_flags = tcp_fin + (tcp_syn << 1) +\
    (tcp_rst << 2) + (tcp_psh << 3) +\
    (tcp_ack << 4) + (tcp_urg << 5)

# the ! in the pack format string means network order
tcp_header = pack(
    '!HHLLBBHHH',
    tcp_source,
    tcp_dest,
    tcp_seq,
    tcp_ack_seq,
    tcp_offset_res,
    tcp_flags,
    tcp_window,
    tcp_check,
    tcp_urg_ptr)

# user_data = 'Hello, how are you'
user_data = ''

# pseudo header fields
source_address = socket.inet_aton(SRC_IP)
dest_address = socket.inet_aton(DST_IP)
placeholder = 0
protocol = socket.IPPROTO_TCP
tcp_length = len(tcp_header) + len(user_data)

psh = pack(
    '!4s4sBBH',
    source_address,
    dest_address,
    placeholder,
    protocol,
    tcp_length)
psh = psh + tcp_header + user_data

tcp_check = checksum(psh)
# print tcp_checksum

# make the tcp header again and fill the correct checksum
# - remember checksum is NOT in network byte order
tcp_header = pack(
    '!HHLLBBH',
    tcp_source,
    tcp_dest,
    tcp_seq,
    tcp_ack_seq,
    tcp_offset_res,
    tcp_flags,
    tcp_window)\
    + pack('H', tcp_check)\
    + pack('!H', tcp_urg_ptr)

# final full packet - syn packets dont have any data
packet = tcp_header + user_data

# Send the packet finally - the port specified has no effect
# put this in a loop if you want to flood the target
s.sendto(packet, (dest_ip, 0))
