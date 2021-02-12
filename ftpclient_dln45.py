# ***Name: Dinh Nguyen
# ***CS472
# ***Homework2 - FTP Client
# *To run the program: python3 ftpclient_dln45.py <server ip/Name> <logfilename> <--portNumber>

# The program will open a socket and ask for user's input for username and password to log in and then,
# connect to the server using the provided credentials. 

# It will then display as a console that wait for user input for commands. 

# Supported commands are: 
# USER, to provide username to server
# PASS, to provide password to server
# CWD,  take one argument, change working directory to the provided directory
# QUIT, close socket and program
# PASV, set server into passive mode
# EPSV, set server into extended passive mode 
# PORT, create new data port/connection with server
# EPRT, create new extended dataport/connection with server
# RETR, retrieve data from server
# STOR, store data to server
# PWD,  show current working directory
# SYST, show operating system type at the server
# LIST, list all files/directories in current directroy or provided directory in its argument 
# HELP, show all supported commands

# All the logs will be stored in the logfilename provided by user. 

import sys
import socket, ssl
import logging
import argparse

MAX_LINE_SIZE = 8192
passive_server = True
encoding = "latin-1"


def ftp_connect(host='', port=0, timeout=None):
    """
    Connect to FTP server. Create a temp file for writing input and output commands
    :param host: server host
    :param port:
    :param timeout:
    :return:
    """
    try:
        if host == '' or port <= 0:
            logging.error("Invalid parameter for connect()")
        sock = socket.create_connection((host, port), timeout)
        af = sock.family
        filebuff = sock.makefile('r', encoding=encoding)
        get_server_response(filebuff)
        return sock, af, filebuff
    except Exception as e:
        logging.error("Exception in connect()")
        logging.exception(e)
        sys.exit(1)


def put_command(sock, line):
    """
    Send a single command line to the server.
    :param sock:
    :param line:
    :return:
    """
    if '\r' in line:
        raise ValueError("Character \\r should not be in line")
    elif '\n' in line:
        raise ValueError('Character \\n should not be in line')
    try:
        line = line + '\r\n'
        sock.sendall(line.encode(encoding))
    except Exception as e:
        logging.error("Exception in putline()")
        logging.exception(e)


def get_line(filebuff):
    """Return one line from server"""
    line = filebuff.readline(MAX_LINE_SIZE + 1)
    if len(line) > MAX_LINE_SIZE:
        raise ValueError("Line is too long (%d bytes)" % MAX_LINE_SIZE)
    elif not line:
        raise EOFError

    if line[-2:] == '\r\n':
        line = line[:-2]
    elif line[-1:] in '\r\n':
        line = line[:-1]
    return line


def get_server_response(filebuff):
    """
    Return response from server.
    """

    # Response from server might contain multiple line. Get one line a time and without \r\n
    resp = get_line(filebuff)
    if resp[3:4] == '-':  # Multiple lines
        code = resp[:3]
        while True:
            next_line = get_line(filebuff)
            resp = resp + ('\n' + next_line)
            if next_line[:3] == code and \
                    next_line[3:4] != '-':
                break

    print(resp)
    c = resp[:1]
    if c in {'1', '2', '3'}:
        logging.debug("Server response: %s" % resp)
        return resp
    else:
        logging.error(resp)
        raise Exception(resp)


def response_2xx(filebuff):
    """Expect a response beginning with '2'."""
    resp = get_server_response(filebuff)
    if resp[:1] != '2':
        raise Exception(resp)
    return resp


def send_command(sock, filebuff, cmd):
    """
    Calling put command to load the command on server.
    :param sock: socket connection
    :param filebuff:
    :param cmd: str
    :return: response from server
    """
    put_command(sock, cmd)
    return get_server_response(filebuff)


def send_command_with_2xx_response(sock, filebuff, cmd):
    """Send a command and expect a response beginning with '2'."""
    put_command(sock, cmd)
    return response_2xx(filebuff)


def send_port_command(sock, filebuff, host, port):
    # Send a port command to server. PORT h1,h2,h3,h4,p1,p2
    host_bytes = host.split('.')
    port_bytes = [repr(port // 256), repr(port % 256)]
    cmd = 'PORT ' + ','.join(host_bytes + port_bytes)
    return send_command_with_2xx_response(sock, filebuff, cmd)


def send_eprt_command(sock, filebuff, host, port):
    # Send a EPRT command to server. E.g: EPRT |1|132.235.1.2|6275| 
    fields = ['', repr(1), host, repr(port), '']
    cmd = 'EPRT ' + '|'.join(fields)
    return send_command_with_2xx_response(sock, filebuff, cmd)


def create_new_socket_and_send_port_cmd(s, af, filebuff):
    # Create and bind new socket for data connection. Send PORT or EPRT command.
    new_sock = None
    error = None
    for resp in socket.getaddrinfo(None, 0, af, socket.SOCK_STREAM, 0, socket.AI_PASSIVE):
        laf, sock_type, proto, _, sa = resp
        try:
            new_sock = socket.socket(laf, sock_type, proto)
            new_sock.bind(sa)
        except OSError as e:
            error = e
            if new_sock:
                new_sock.close()
            new_sock = None
            continue
        break

    if new_sock is None:
        if error is not None:
            raise error
        else:
            raise Exception("getaddrinfo returns an empty list")

    new_sock.listen(1)
    port = new_sock.getsockname()[1]
    host = s.getsockname()[0]
    if af == 2:
        logging.debug("Sending PORT to %s, port %s" % (host, port))
        send_port_command(s, filebuff, host, port)
    else:
        logging.debug("Sending EPRT to %s, port %s" % (host, port))
        send_eprt_command(s, filebuff, host, port)
    return new_sock


def send_passive_command(sock, af, filebuff):
    # Apply passive/extend passive mode to the server
    if af == 2:
        host, port = get_host_port_277(send_command(sock, filebuff, 'PASV'))
    else:
        host, port = get_host_port_229(send_command(sock, filebuff, 'EPSV'), sock.getpeername())
    return host, port


def check_response(resp, filebuff):
    # CHeck the reponse's code header
    if resp[0] == '2':
        resp = get_server_response(filebuff)
    if resp[0] != '1':
        raise Exception(resp)


def load_command(s, af, filebuff, cmd):
    # Load the command to the server using PORT if server is active
    
    global passive_server
    if passive_server:
        try:
            host, port = send_passive_command(s, af, filebuff)
            conn = socket.create_connection((host, port), timeout=1)
            logging.debug("Sending command: %s" % cmd)
            resp = send_command(s, filebuff, cmd)
            check_response(resp, filebuff)
            return conn

        except Exception as e:
            logging.exception(e)


def login(sock, filebuff, user='', passwd=''):
    '''Login, default anonymous.'''
    logging.info("Logging in to host")
    if not user:
        user = 'cs472'
    if not passwd:
        passwd = ''
    logging.debug("Using username: %s, password: %s" % (user, passwd))
    try:
        resp = send_command(sock, filebuff, 'USER ' + user)
        resp = send_command(sock, filebuff, 'PASS ' + passwd)
        if resp[0] != '2':
            logging.error(resp)
            raise Exception(resp)
        return resp
    except Exception as e:
        logging.error("Exception in login()")
        logging.exception(e)


def retr_bin(sock, af, filebuff, cmd, callback, blocksize=8192):

    logging.info("Inside retr_bin()")
    try:
        send_command_with_2xx_response(sock, filebuff, 'TYPE I')
        with load_command(sock, af, filebuff, cmd) as conn:
            while True:
                data = conn.recv(blocksize)
                if not data:
                    break
                callback(data)
        return response_2xx(filebuff)
    except Exception as e:
        logging.error("Exception in retr_bin()")
        logging.exception(e)


def retr_bylines(sock, af, filebuff, cmd):

    send_command(sock, filebuff, 'TYPE A')
    with load_command(sock, af, filebuff, cmd) as conn, conn.makefile('r', encoding=encoding) as fp:
        while True:
            line = fp.readline(MAX_LINE_SIZE + 1)
            if len(line) > MAX_LINE_SIZE:
                logging.error("got more than %d bytes" % MAX_LINE_SIZE)
                raise Exception("got more than %d bytes" % MAX_LINE_SIZE)
            if not line:
                break
            if line[-2:] == '\r\n':
                line = line[:-2]
            elif line[-1:] == '\n':
                line = line[:-1]
            print(line)
    return response_2xx(filebuff)


def stor_inbin(sock, af, filebuff, cmd, fp, blocksize=8192, callback=None):

    logging.info("Inside stor_inbin()")
    try:
        send_command_with_2xx_response(sock, filebuff, 'TYPE I')
        with load_command(sock, af, filebuff, cmd) as conn:
            while 1:
                buffer = fp.read(blocksize)
                if not buffer:
                    break
                conn.sendall(buffer)
                if callback:
                    callback(buffer)
        return response_2xx(filebuff)
    except Exception as e:
        logging.error("Exception in stor_inbin()")
        logging.exception(e)


def quit(sock, filebuff):
    resp = send_command_with_2xx_response(sock, filebuff, 'QUIT')
    sock.close()
    return resp


reply_227 = None


def get_host_port_277(resp):

    if resp[:3] != '227':
        logging.error(resp)
        raise Exception(resp)
    global reply_227
    if reply_227 is None:
        import re
        reply_227 = re.compile(r'(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)', re.ASCII)
    m = reply_227.search(resp)
    if not m:
        logging.error(resp)
        raise Exception(resp)
    numbers = m.groups()
    host = '.'.join(numbers[:4])
    port = (int(numbers[4]) << 8) + int(numbers[5])
    return host, port


def get_host_port_229(resp, peer):
    if resp[:3] != '229':
        logging.error(resp)
        raise Exception(resp)
    left = resp.find('(')
    if left < 0:
        logging.error(resp)
        raise Exception(resp)
    right = resp.find(')', left + 1)
    if right < 0:
        logging.error(resp)
        raise Exception(resp)  # should contain '(|||port|)'
    if resp[left + 1] != resp[right - 1]:
        logging.error(resp)
        raise Exception(resp)
    parts = resp[left + 1:right].split(resp[left + 1])
    if len(parts) != 5:
        logging.error(resp)
        raise Exception(resp)
    host = peer[0]
    port = int(parts[3])
    return host, port


def init_client():
    parser = argparse.ArgumentParser()
    parser.add_argument('ServerIP/Name')
    parser.add_argument('logFile')
    parser.add_argument('portNumber')
    args = vars(parser.parse_args())

    hostname = args['ServerIP/Name']  # sys.argv[1]
    logFile = args['logFile']
    port = int(args['portNumber'])

    # logging
    logging.basicConfig(filename=logFile, filemode='a', level=logging.DEBUG,
                        format='[%(asctime)s] [%(funcName)s] [%(levelname)s] %(message)s', datefmt="%Y-%m-%d %H:%M:%S")
    logging.info("********************************WELCOME*********************************")
    # start ftp client session
    try:
        logging.info("Creating socket to host")
        host = socket.gethostbyname(hostname)
        logging.debug("Connecting to host,port: %s, %s" % (host, port))
        sock, af, filebuff = ftp_connect(host, port)
        user = input("Please enter username: ")
        pw = input("Please enter password: ")
        login(sock, filebuff, user, pw)
        while 1:
            cmd = get_command()
            parsecmd(sock, af, filebuff, cmd)
            if cmd in ["quit", "exit", "QUIT", "EXIT"]:
                break
    except Exception as e:
        logging.error("Exception in init_client() function")
        logging.exception(e)
        sys.exit(1)


# Get a command from the user.
def get_command():
    try:
        while 1:
            line = input('ftpclient> ')
            if line:
                logging.debug("Command received: %s" % line)
                return line
    except EOFError as e:
        logging.exception(e)
        return ''


# Parse input cmd
def parsecmd(sock, af, filebuff, cmd):
    global passive_server
    try:
        logging.info("Inside parsecmd()")
        logging.debug("Received command from user: %s" % cmd)

        if "LIST" in cmd or "list" in cmd:
            retr_bylines(sock, af, filebuff, cmd)

        elif cmd in ["quit", "exit", "QUIT", "EXIT"]:
            quit(sock, filebuff)

        elif "RETR" in cmd or "retr" in cmd:
            cmd_list = cmd.split(" ")
            with open(cmd_list[1], 'wb') as fp:
                retr_bin(sock, af, filebuff, cmd, fp.write)

        elif "STOR" in cmd or "stor" in cmd:
            cmd_list = cmd.split(" ")
            with open(cmd_list[1], 'rb') as fp:
                stor_inbin(sock, af, filebuff, cmd, fp)
        elif "PORT" in cmd or "port" in cmd:
            create_new_socket_and_send_port_cmd(sock, af, filebuff)
        elif "EPRT" in cmd or "eprt" in cmd:
            create_new_socket_and_send_port_cmd(sock, af, filebuff)
        else:
            res = send_command(sock, filebuff, cmd)
            logging.debug("Server response: %s" % res)

    except Exception as e:
        logging.error("Exception in parsecmd()")
        logging.exception(e)


if __name__ == '__main__':
    init_client()
