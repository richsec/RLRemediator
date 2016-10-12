from random import randint

# please install the pxssh by
# "sudo pip install pexpect"
from pexpect import pxssh
from time import time

HOST_W_OPEN = '54.208.220.41'
PORT_W_OPEN = 22
HOST_W_CLOSE = '52.45.56.227'
PORT_W_CLOSE = 2020


def make_ssh(host, user, pwd, port=22):
    try:
        s = pxssh.pxssh()
        s.force_password = True
        s.login(host, user, pwd, port=port)
        s.sendline('uptime')   # run a command
        s.prompt()             # match the prompt
        print(s.before)        # print everything before the prompt.
        s.logout()
    except pxssh.ExceptionPxssh as e:
        print("pxssh failed on login with user %s, pwd %s." % (user, pwd))
        print(e)


def generate_faked_user():
    user = 'fk-'
    length = randint(3, 8)
    for i in range(0, length):
        rand = randint(97, 122)
        user += str(unichr(rand))
    return user


def generate_faked_pwd():
    pwd = ''
    length = randint(3, 10)
    for i in range(0, length):
        rand = randint(97, 122)
        pwd += str(unichr(rand))
    return pwd


if __name__ == "__main__":
    host = HOST_W_OPEN
    port = PORT_W_OPEN
    # host = HOST_W_CLOSE
    # port = PORT_W_CLOSE
    real_user = 'rl-hao'
    real_pwd = 'redlocktesthao'
    num_users = 50
    num_tries = 3

    start = time()
    print '>>>>start time: ' + str(start)

    for i in range(0, num_users):
        user = generate_faked_user()
        for j in range(0, num_tries):
            print '>>> #%d ssh attemp <<<' % (i * num_tries + j + 1)
            pwd = generate_faked_pwd()
            make_ssh(host, user, pwd)

    # simluate the event that the true password found
    print '>>> Password found! <<<'
    make_ssh(host, real_user, real_pwd, port)

    print '>>>>start time: ' + str(start)
    print '>>>>end time: ' + str(time())

