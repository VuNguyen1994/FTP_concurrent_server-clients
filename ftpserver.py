# Name: Dinh Nguyen
# CS 472 FTP Server
# To run server: python3 <serverfile> <logFile> <portNumber> 
# Example: python3 ftpserver.py serverlog.txt 50007

import socket, ssl
import os
import logging
import argparse
import sys
import threading
import subprocess
import bcrypt

MAX_LINE_SIZE = 8193
authorized_users = {}
authorized_users_hash = []
passive_server = True       
pasv_mode=True              # Default pasv_mode=Yes
port_mode = False           # Default port_mode=No
ssl_mode = False            # Default ssl_mode=No
TIMEOUT = 10
MAX_CLIENT = 5
count = 0               # number of clients connected count
SUPPORT_CMD = ['USER', 'PASS', 'CWD', 'CDUP', 'QUIT', 'PASV', 'EPSV', 'PORT', 'EPRT', 'RETR', 'STOR', 'PWD', 'LIST']


def get_accounts_dict(filename):
    """Update Authorized Users dictionary"""
    try:
        logging.info("Inside get_accounts_dict()")
        global authorized_users
        with open(filename, 'r') as account_file:
            account = account_file.readline(MAX_LINE_SIZE)
            while account:
                if len(account) > MAX_LINE_SIZE:
                    raise ValueError("account is too long (%d bytes)" % MAX_LINE_SIZE)
                if account[-2:] == '\r\n':
                    account = account[:-2]
                elif account[-1:] in '\r\n':
                    account = account[:-1]
                username = account.split("/")[0]
                password = account.split("/")[1]
                authorized_users.update({username: password})
                account = account_file.readline(MAX_LINE_SIZE)
    except Exception as e:
        logging.error("Exception in get_accounts_dict()")
        logging.exception(e)


def get_line(buf_file):
    """Return one line at a time from file buffer associated with the socket"""
    logging.info("Inside get_line()")
    line = buf_file.readline(MAX_LINE_SIZE).decode("latin-1")
    if len(line) > MAX_LINE_SIZE:
        raise ValueError("Line is too long (%d bytes)" % MAX_LINE_SIZE)
    elif not line:
        raise EOFError

    if line[-2:] == '\r\n':
        line = line[:-2]
    elif line[-1:] in '\r\n':
        line = line[:-1]
    return line


def authenticate(user_cmd, pw_cmd):
    """Check if client side is valid and authenticated
        Parse USER command and PASS command
        Username and password must be in the authorized_users dictionary"""
    try:
        global authorized_users
        logging.info("Inside authenticate()")
        logging.debug("User command received: " + user_cmd)
        logging.debug("Password command received: " + pw_cmd)
        username = (user_cmd.split(' '))[1]
        logging.debug('Provided username:' + username + '.\n')
        pw = (pw_cmd.split(' '))[1]
        hashed_pw = bcrypt.hashpw(pw.encode(), bcrypt.gensalt(14))
        logging.debug('Provided password:' + hashed_pw.decode() + '.\n')
        if username in authorized_users:
            logging.debug('username: ' + '"' + username + '"' + " is valid")
            if bcrypt.checkpw(authorized_users[username].encode(), hashed_pw):
                logging.debug("Authentication completed successfully")
                return True
            else:
                logging.error("Authentication Failed. Wrong Password.")
                return False
        else:
            logging.error("Provided username is invalid: " + username)
            return False
    except Exception as e:
        logging.error("Exception in authenticate()")
        logging.exception(e)


def init_data_conn(conn, client_host, data_port):
    """Check for passive and Create new data connection."""
    try:
        global passive_server
        logging.info("Inside init_data_conn()")
        host = ''
        # Data port 256x x1 + x2
        if passive_server:
            # conn.sendall('200 PORT command successful. Consider using PASV.\r\n'.encode("latin-1"))
            data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            data_sock.bind((host, data_port))
            data_sock.settimeout(2)
            data_sock.listen(1)
            data_conn, addr = data_sock.accept()
            data_file = data_conn.makefile('r')
            return data_conn, data_file
        elif client_host and not passive_server:
            conn.sendall('200 PORT command successful. Consider using PASV.\r\n'.encode("latin-1"))
            # data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # data_sock.bind((host, data_port))
            # data_sock.settimeout(2)
            # data_sock.listen(1)
            # data_conn, addr = data_sock.accept()
            # data_file = data_conn.makefile('r')
            # return data_conn, data_file
            data_conn = socket.create_connection((client_host, data_port), timeout=1)
            return data_conn

    except Exception as e:
        logging.error("Exception in init_data_conn()")
        logging.exception(e)


def server_init(port):
    """Init FTP server environment
        Open sockets, listen, check authentication and accept connection from clients"""
    global passive_server, TIMEOUT, count, dfa_state
    try:
        print("Welcome to DLN45 FTP Server - CS472\n")
        logging.info("Inside server_init()")
        logging.debug("FTP Port used: " + str(port))
        host = ''                 # Symbolic name meaning all available interfaces
        # PORT = 50007              # Arbitrary non-privileged port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, port))
            # s.settimeout(TIMEOUT)
            logging.debug("Server socket opened (timeout=" + str(TIMEOUT) + "). Listening for connection...")
            s.listen(MAX_CLIENT)
            threads = [i for i in range(0, MAX_CLIENT)]
            while True:
                conn, addr = s.accept()
                if ssl_mode:
                    connstream = ssl.wrap_socket(conn, server_side=True,certfile="cert.pem",keyfile="cert.pem",ssl_version=ssl.PROTOCOL_TLSv1)
                    conn = connstream
                while conn and addr and count < MAX_CLIENT:
                    logging.debug("Main: Creating thread for: " + str(addr[0]))
                    threads[count] = threading.Thread(target=work_with_client, args=(conn, addr))
                    logging.debug("Main: Starting thread for: " + str(addr[0]))
                    threads[count].start()
                    count += 1
                    conn, addr = s.accept()
                # logging.info("Main: Wait for the threads to finish")
                # for td in range(0, MAX_CLIENT):
                #     threads[td].join()
            # logging.info("Socket Server close.")
    except Exception as e:
        logging.error("Exception in server_init()")
        logging.exception(e)


def work_with_client(conn, addr):
    """Main procedure parsing commands and return responses for each client"""
    global passive_server, count
    logging.info("Inside work_with_client()")
    try:
        print("Connected from : ", str(addr[0]))
        dfa_state = 'IDLE'
        logging.debug(">>> Entering FTP state " + dfa_state)
        data_port = int(addr[1] + 10)
        logging.debug("Connected from: " + str(addr[0]) + ". Data_port: " + str(data_port))
        with conn:
            buf_file = conn.makefile('rb')
        data = '220 Welcome to DLN45 FTP Server - CS472.\r\n'.encode("latin-1")
        conn.sendall(data)
        dfa_state = 'AUTHENTICATE'
        logging.debug(">>> Entering FTP state " + dfa_state)
        # login for client
        while dfa_state != 'CONNECTED':
            line=get_line(buf_file)
            cmd = line.split(" ")[0]
            if cmd == 'USER' or cmd == 'user':
                user_cmd = line
                conn.sendall('331 Please specify the password.\r\n'.encode("latin-1"))
                pw_cmd = get_line(buf_file)
                if authenticate(user_cmd, pw_cmd):
                    conn.sendall('230 Login Successful.\r\n'.encode("latin-1"))
                    dfa_state = 'CONNECTED'
                else:
                    conn.sendall('550 Login Incorrect.\r\n'.encode("latin-1"))
            if cmd == 'PASS' or cmd == 'pass':
                pw_cmd = line
                conn.sendall('331 Please specify the user.\r\n'.encode("latin-1"))
                user_cmd = get_line(buf_file)
                if authenticate(user_cmd, pw_cmd):
                    conn.sendall('230 Login Successful.\r\n'.encode("latin-1"))
                    dfa_state = 'CONNECTED'
                else:
                    conn.sendall('550 Login Incorrect.\r\n'.encode("latin-1"))
            if cmd == 'QUIT' or cmd == 'quit':
                print("Disconnected from: ", str(addr[0]))
                logging.debug("Disconnected from: " + str(addr[0]))
                break

        while dfa_state == 'CONNECTED':
            logging.debug(">>> Entering FTP state " + dfa_state)
            line = get_line(buf_file)
            cmd = line.split(" ")[0]
            if cmd == 'QUIT' or cmd == 'quit':
                conn.sendall("221 Goodbye.\r\n".encode("latin-1"))
                print("Disconnected from: ", str(addr[0]))
                logging.debug("Disconnected from: " + str(addr[0]))
                dfa_state = 'END'
                logging.debug(">>> Entering FTP state " + dfa_state)
                break
            elif cmd == 'USER' or cmd == 'user':
                user_cmd = line
                conn.sendall('331 Please specify the password.\r\n'.encode("latin-1"))
                pw_cmd = get_line(buf_file)
                if authenticate(user_cmd, pw_cmd):
                    conn.sendall('230 Login Successful.\r\n'.encode("latin-1"))
                else:
                    conn.sendall('550 Login Incorrect.\r\n'.encode("latin-1"))
            elif cmd == 'PASS' or cmd == 'pass':
                pw_cmd = line
                conn.sendall('331 Please specify the user.\r\n'.encode("latin-1"))
                user_cmd = get_line(buf_file)
                if authenticate(user_cmd, pw_cmd):
                    conn.sendall('230 Login Successful.\r\n'.encode("latin-1"))
                else:
                    conn.sendall('550 Login Incorrect.\r\n'.encode("latin-1"))
            elif cmd == 'PWD' or cmd == 'pwd':
                conn.sendall(('257 ' + '"' + os.getcwd() + '"' + ' is current directory.\r\n').encode("latin-1"))
            elif cmd == 'CDUP' or cmd == 'cdup':
                os.chdir('../')
                conn.sendall('250 Directory successfully changed.\r\n'.encode("latin-1"))
            elif cmd == 'cd' or cmd == 'CD' or cmd == 'CWD' or cmd == 'cwd':
                new_dir = line.split(" ")[1]
                os.chdir('./' + new_dir)
                conn.sendall('250 Directory successfully changed.\r\n'.encode("latin-1"))
            elif 'TYPE A' in line:
                conn.sendall('200 Switching to ASCII mode.\r\n'.encode("latin-1"))
                line = get_line(buf_file)
                if 'PASV' in line or 'pasv' in line:
                    passive_server = True
                    host_ip = str(addr[0])  
                    ips = host_ip.split(".")
                    # data_port = 50005
                    ips.append(str(data_port // 256))
                    ips.append(str(data_port % 256))
                    conn.sendall(
                        ('227 Entering Passive Mode ' + '(' + ','.join(ips) + ')' + '.\r\n').encode("latin-1"))
                if 'EPSV' in line or 'epsv' in line:
                    passive_server = True
                    conn.settimeout(2 * TIMEOUT)
                    # data_port = 50005
                    conn.sendall(
                        ('229 Entering Extended Passive Mode ' + '(|||' + str(data_port) + '|)\r\n').encode(
                            "latin-1"))
                    data_conn, data_file = init_data_conn(conn, None, data_port)
            elif 'TYPE I' in line:
                conn.sendall('200 Switching to Binary mode.\r\n'.encode("latin-1"))
                line = get_line(buf_file)
                if 'PASV' in line or 'pasv' in line:
                    passive_server = True
                    host_ip = str(addr[0])
                    ips = host_ip.split(".")
                    # data_port = 50005
                    ips.append(str(data_port // 256))
                    ips.append(str(data_port % 256))
                    conn.sendall(
                        ('227 Entering Passive Mode ' + '(' + ','.join(ips) + ')' + '.\r\n').encode("latin-1"))
                if 'EPSV' in line or 'epsv' in line:
                    passive_server = True
                    conn.settimeout(2 * TIMEOUT)
                    # data_port = 50005
                    conn.sendall(
                        ('229 Entering Extended Passive Mode ' + '(|||' + str(data_port) + '|)\r\n').encode(
                            "latin-1"))
                    data_conn, data_file = init_data_conn(conn, None, data_port)

            elif cmd == 'LIST' or cmd == 'list':
                cmd = line  # Get full cmd
                conn.sendall('150 Here comes the directory listing\r\n'.encode("latin-1"))
                # all_files = os.listdir(".")
                all_files = subprocess.check_output(["ls", "-l"])
                files = all_files.decode()
                logging.debug('all files in directory: ' + files)
                data_conn.send(all_files)
                data_conn.send('226 Directory send OK.\r\n'.encode("latin-1"))
                data_conn.send(b'')  # Send EOF
                # data_sock.close()

            elif cmd == 'PASV' or cmd == 'pasv':
                if pasv_mode:
                    passive_server = True
                    host_ip = str(addr[0]) 
                    ips = host_ip.split(".")
                    # data_port = 50005
                    ips.append(str(data_port // 256))
                    ips.append(str(data_port % 256))
                    conn.sendall(('227 Entering Passive Mode ' + '(' + ','.join(ips) + ')' + '.\r\n').encode("latin-1"))
                else:
                    conn.sendall('502 Command not implemented. Unsupported server mode\r\n'.encode("latin-1"))
            elif cmd == 'EPSV' or cmd == 'epsv':
                if pasv_mode:
                    passive_server = True
                    conn.settimeout(2 * TIMEOUT)
                    # data_port = 50005
                    conn.sendall(('229 Entering Extended Passive Mode ' + '(|||' + str(data_port) + '|)\r\n').encode("latin-1"))
                else:
                    conn.sendall('502 Command not implemented. Unsupported server mode\r\n'.encode("latin-1"))
            elif cmd == 'PORT' or cmd == 'port':
                if port_mode:
                    passive_server = False
                    new_port1 = int((line.split(" ")[1]).split(',')[-2])
                    new_port2 = int((line.split(" ")[1]).split(',')[-1])
                    new_data_port = new_port1*256 + new_port2
                    client_host = '.'.join((line.split(" ")[1]).split(',')[:4])
                    logging.debug("clientIP: " + str(client_host))
                    logging.debug("new data_port: " + str(new_data_port))
                    data_conn = init_data_conn(conn, client_host, new_data_port)
                else:
                    conn.sendall('502 Command not implemented. Unsupported server mode\r\n'.encode("latin-1"))
            elif cmd == 'EPRT' or cmd == 'eprt':
                if port_mode:
                    passive_server = False
                    new_port1 = int((line.split(" ")[1]).split(',')[-2])
                    new_port2 = int((line.split(" ")[1]).split(',')[-1])
                    new_data_port = new_port1*256 + new_port2
                    client_host = '.'.join((line.split(" ")[1]).split(',')[:4])
                    logging.debug("clientIP: " + str(client_host))
                    logging.debug("new data_port: " + str(new_data_port))
                    data_conn = init_data_conn(conn, client_host, new_data_port)
                else:
                    conn.sendall('502 Command not implemented. Unsupported server mode\r\n'.encode("latin-1"))
            elif cmd == 'RETR' or cmd == 'retr':
                target_file = os.getcwd() + '/' + line.split(' ')[1]
                size = str(os.path.getsize(target_file))
                conn.sendall(('150 Opening BINARY mode data connection for' + line.split(' ')[
                    1] + '(' + size + 'bytes).\r\n').encode("latin-1"))
                with open(target_file, 'rb') as f:
                    data_conn.sendfile(f, offset=0)
                data_conn.send(b'')  # Send EOF
                conn.sendall('226 Transfer complete.'.encode("latin-1"))
                # data_sock.close()
            elif cmd == 'STOR' or cmd == 'stor':
                target_file = os.getcwd() + '/' + line.split(' ')[1]
                conn.sendall('150 OK to send data.'.encode("latin-1"))
                with open(target_file, 'w') as f:
                    read_line = get_line(data_file)
                    while read_line:
                        read_line += '\r\n'
                        f.writelines(read_line)
                        read_line = get_line(data_file)
                conn.sendall('226 Transfer complete.'.encode("latin-1"))
                # data_sock.close()
            elif cmd not in SUPPORT_CMD:
                conn.sendall('?Invalid command\r\n'.encode("latin-1"))
        count -= 1      # Client exit, update counter.
    except Exception as e:
        count -= 1      # Client exit, update counter.
        logging.error("Exception in work_with_client()")
        logging.exception(e)


def parse_config_file():
    """ Parse ftp server config file (default: /home/user/ftpserver.conf) line by line
        Raise error and exit if fail
        Ignore lines with # or comments. """
    try:
        global pasv_mode, port_mode
        logging.info("Inside parse_config()")
        homedir = os.path.expanduser("~")
        config_file = homedir + "/" + "ftpserver.conf"
        logging.debug("Default location: " + config_file)
        with open(config_file, 'r') as f:
            logging.debug("Reading Server FTP config file: ")
            rline = f.readline()
            while rline and rline != "\n":
                if rline[0] != "#":
                    logging.debug(rline)
                    set_config(rline)
                rline = f.readline()
        logging.debug("Applying FTP server config completed.")
        if not port_mode and not pasv_mode:
            raise ValueError("Fatal Error: Server must have at least one mode (Pasv or Port).")
            sys.exit(1)
    except Exception as e:
        logging.error("Exception in parse_config()")
        logging.exception(e)
        sys.exit(1)

def set_config(rline):
    """Handle each line of config file. Set according config"""
    global pasv_mode, port_mode, ssl_mode
    try:
        logging.info("Inside set_config()")
        attribute = rline.split("=")[0].strip()
        value = rline.split("=")[1].strip()
        logging.debug("Attribute: " + attribute + ". Value: " + value + ".")
        if attribute=="pasv_mode":
            if value == "Yes" or value == "YES":
                pasv_mode = True
                logging.debug("Attribute " + attribute + " SET!")
            elif value == "No" or value == "NO":
                pasv_mode = False
                logging.debug("Attribute " + attribute + " RESET!")
            else:
                logging.error("Invalid value for pasv_mode in config file")
        if attribute=="port_mode":
            if value == "Yes" or value == "YES":
                port_mode = True
                logging.debug("Attribute " + attribute + " SET!")
            elif value == "No" or value == "NO":
                port_mode = False
                logging.debug("Attribute " + attribute + " RESET!")
            else:
                logging.error("Invalid value for port_mode in config file")
        if attribute=="ssl_mode":
            if value == "Yes" or value == "YES":
                ssl_mode = True
                logging.debug("Attribute " + attribute + " SET!")
            elif value == "No" or value == "NO":
                ssl_mode = False
                logging.debug("Attribute " + attribute + " RESET!")
            else:
                logging.error("Invalid value for ssl_mode in config file")

    except Exception as e:
        logging.error("Exception in set_config()")
        logging.exception(e)


if __name__ == '__main__':
    # Parsing arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('logFile')
    parser.add_argument('portNumber')
    args = vars(parser.parse_args())

    logFile = args['logFile']
    ftp_port = int(args['portNumber'])
    
    # logging
    logging.basicConfig(filename=logFile, filemode='a', level=logging.DEBUG,
                        format='[%(asctime)s] [%(funcName)s] [%(levelname)s] %(message)s', datefmt="%Y-%m-%d %H:%M:%S")
    logging.info("\n********************************WELCOME*********************************")
    
    # read and apply config file
    parse_config_file()

    # get accounts info from accounts file
    get_accounts_dict('ftp_accounts.txt')
    
    # start ftp server session
    server_init(ftp_port)
    sys.exit(0)
