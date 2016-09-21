import socket

from time import sleep
from random import randint

HOST_W_OPEN = '54.208.220.41'
HOST_W_CLOSE = '52.45.56.227'
WORKDAY_HOST = '54.187.235.74'

num_conn = 100


def make_tcp_connections(host, port, num_conn):
    # src_port = randint(50000, 59999)
    for i in range(0, num_conn):
        try:
            sleep(0.1)
            print '#%d establishing TCP connection to %s:%s ...' % (
                i, host, port)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # s.bind(('', src_port))
            print '--- binded the port'
            s.connect((host, port))
            print '--- connection established'
            # close right after the connection
            # such connection is hard to distinguish
            # from the rejected TCP connection
            s.close()
            print '--- connection closed'
        except Exception as e:
            print 'Failed to connection to %s:%s, error %s' % (host, port, e)

# # port 80
# make_tcp_connections(HOST_W_OPEN, 80, num_conn)

# # port 443
# make_tcp_connections(HOST_W_OPEN, 443, num_conn)

# # port 22
# make_tcp_connections(HOST_W_OPEN, 22, num_conn)

# # port 80
# make_tcp_connections(HOST_W_CLOSE, 80, num_conn)

# # port 443
# make_tcp_connections(HOST_W_CLOSE, 443, num_conn)

# # port 22
# make_tcp_connections(HOST_W_CLOSE, 22, num_conn)

# Workday Host
make_tcp_connections(WORKDAY_HOST, 443, 5)
