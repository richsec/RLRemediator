import requests
import subprocess
import sys
from time import sleep

HOST_W_OPEN = '54.208.220.41'
HOST_W_CLOSE = '52.45.56.227'

host = HOST_W_OPEN
num_conn = 100

# 80 port
url = 'http://' + host + ':80'
for i in range(0, num_conn):
    try:
        sleep(0.1)
        print '#' + str(i) + ' connection to ' + url + ' ...'
        r = requests.get(url)
        print '-- get response of length ' + str(len(r.text))
    except Exception as e:
        print '-- failed to connect to ' + url

# 443 port
url = 'https://' + host + ':443'
for i in range(0, num_conn):
    try:
        sleep(0.1)
        print '#' + str(i) + ' connection to ' + url + ' ...'
        r = requests.get(url)
        print '-- get response of length ' + str(len(r.text))
    except Exception as e:
        print '-- failed to connect to ' + url

# 22 port
user = 'foo'
url = user + '@' + host
COMMAND = "uname -a"
for i in range(0, num_conn):
    try:
        sleep(0.1)
        print '#' + str(i) + ' SSH to ' + url + ' ...'
        # call(['ssh', url, '-p 22'])
        ssh = subprocess.Popen(
            ["ssh", url, '-p 22', COMMAND],
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        result = ssh.stdout.readlines()
        if result == []:
            error = ssh.stderr.readlines()
            print >>sys.stderr, "ERROR: %s" % error
        else:
            print result
    except Exception as e:
        print '-- failed to SSH to ' + url + ', error' + str(e)
