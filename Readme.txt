***Name: Dinh Nguyen
***CS472
***Homework3 - FTP Server
# To run server: python3 <serverfile> <logFile> <ftpportNumber> 
# Example: python3 ftpserver.py serverlog.txt 50007

# The server program will parse the config file at /home/<user>/ftpserver.conf
# The program will open a socket and listen to any connection from clients. 
# The program currently supports 5 maximum clients.
# All password provided will be secured and encrypted by bcrypt python lib

# To connect to the server, run the ftp client with the same port and the server IP
# Example: python3 ftpclient.py <serverIP> clientlog.txt 50007

The client will have to enter their user/password and send to the server 
Using the provided credentials in the ftp_accounts.txt file which lists all valid creds
The server will check if the credentials provided from the client is valid.

Supported commands are: 
USER, to provide username to server
PASS, to provide password to server
CWD,  take one argument, change working directory to the provided directory
CPUD, go up 1 directory
QUIT, close socket and program
PASV, set server into passive mode
EPSV, set server into extended passive mode 
PORT, create new data port/connection with server
EPRT, create new extended dataport/connection with server
RETR, retrieve data from server
STOR, store data to server
PWD,  show current working directory
LIST, list all files/directories in current directroy or provided directory in its argument 


All the logs will be stored in the logfilename provided by user.

*** Current Bug:
- The client may not be able to detect the EOF from the server when 
running with LIST, RETR and STOR commands. If so, client will wait for EOF from server
until it timeout the data connection. 
