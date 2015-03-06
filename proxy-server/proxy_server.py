#!/usr/bin/python
#
# Simple HTTP proxy server
# Author: Hannah Brock
#
# Extended from skeleton code from Kurose and Ross

from socket import *
import sys
import thread
import os

BAD_REQUEST = "HTTP/1.0 400 Bad Request\r\nContent-Type:text/html\r\n\r\n400 Bad Request"
UNSUPPORTED = "HTTP/1.0 501 Unimplemented\r\nContent-Type:text/html\r\n\r\n501 Unimplemented"
OK = "HTTP/1.0 200 OK\r\nContent-Type:text/html\r\n\r\n"
NOT_FOUND = "HTTP/1.0 404 Not found\r\nContent-Type:text/html\r\n\r\n404 Not Found"

# send
# Sends a message through a socket until all
# bytes have been sent.
#
# msg: message to send
# sock: socket to send through
# Returns the number of bytes sent
def sendMsg(msg, sock):
    msglen = len(msg)
    totalsent = 0
    while (totalsent < msglen):
        sent = sock.send(msg[totalsent:])
        if sent == 0:
            return totalsent
        totalsent = totalsent + sent
    return totalsent

# recvMsg
# Receives a full message from a socket.
#
# sock: socket to receive from
def recvMsg(sock):
    msg = ""
    recvd = sock.recv(4096)
    while (len(recvd) > 0):
        msg = msg + recvd
        recvd = sock.recv(4096)
    return msg

# findHostname
# Finds the hostname in a request header
# that has been modified to be the correct
# format
#
# header: the request header
# Returns the hostname or none if not found
def findHostname(header):
    headerLines = header.split("\r\n")
    for line in headerLines:
        if line.find("Host:") != -1:
            return line.split("Host:")[1].strip()
    return None

# modifyHeader
# Returns a modified header, always using the 
# Host header line
#
# msg: the message containing the headers
# Returns new headers. Returns none if there is
# no host specified
def modifyHeader(msg):
    header = msg.split("\r\n\r\n")[0]
    headerLines = header.split("\r\n")
    headerLines[0] = headerLines[0].replace("1.1", "1.0")
    headerFound = False
    for x in range(1,len(headerLines)):
        # found host line, so return header as is
        if headerLines[x].find("Host:") != -1:
            headerFound = True
        elif headerLines[x].lower().find("accept-encoding") != -1:
            headerLines[x] = "Accept-Encoding: identity"
        elif headerLines[x].lower().find("connection:") != -1:
            headerLines[x] = "Connection: close"
        # if we find a malformed line, return none
        if len(headerLines[x].split(":")) < 2 and headerLines[x] != "":
            return None
    try:
        splitmsg = headerLines[0].split()[1].split("//")[1]
        host = splitmsg.partition("/")[0]
        url = "/"+splitmsg.partition("/")[2]
    except IndexError:
        if not headerFound:
            return None
    headerLines[0] = "GET " + url + " HTTP/1.0"
    if not headerFound:
        headerLines.insert(1, "Host: "+host)
    return "\r\n".join(headerLines)
    
# getFilename
# Gets appropriate cache file name
#
# header: header from message
# Returns the filename to be used
def getFilename(header):
    hostname = findHostname(header)
    if hostname is None:
        return None
    requestLine = header.split("\r\n")[0]
    return hostname + requestLine.split(" ")[1]

# checkCache
# Reads a file from the cache.
#
# filename: filename to read
# Returns the data if the file exists, or null.
def checkCache(filename):
    filetouse = "/" + filename + "CACHEFILE"
    try:
        # Check whether the file exists in the cache
        f = open(filetouse[1:], "r")
        outputdata = f.read()
        f.close()
        return outputdata
    except IOError:
        return None

# writeToCache
# Writes a file to the cache
#
# path: the file to write to
# data: the data to write
def writeToCache(path, data):
    try:
        if not os.path.exists(path):
            os.makedirs(path)
        f = open(path+"CACHEFILE", "w")
        f.write(data);
        f.close();
    except IOError:
        if not QUIET:
            print 'Failed to write file to cache at: '+path
    except OSError:
        if not QUIET:
            print 'Could not write to cache: filename too long'

# checkRequest
# Checks if a request is valid.
#
# msg: msg with request
# Returns modified headers if the request is valid
# Returns None if this is a malformed request
# Returns "UNSUPPORTED" if the command is unsupported
def checkRequest(msg):
    firstLine = msg.split("\r\n")[0].split()
    if len(firstLine) != 3:
        return None
    if (firstLine[2] != "HTTP/1.0") and (firstLine[2] != "HTTP/1.1"):
        return None
    if (firstLine[0] != "GET"):
        return "UNSUPPORTED"
    header = modifyHeader(msg)
    if header is None:
        return None
    return header

# getPort
# Gets a port number from the given string
#
# Returns -1 if the string is does not
# contain a port
def getPort(s):
    try:
        p = s.split(":")[1]
        return int(p)
    except (ValueError, IndexError):
        return -1

# getFromServer
# Forwards a request on to a remote server
#
# header: request
# filename: filename to write to for caching
# Returns the message to send back to the client
def getFromServer(header, filename):
    # Create a socket on the proxyserver
    proxy = socket(AF_INET, SOCK_STREAM) 
    try:
        hostn = findHostname(header)
        # Get port
        serverport = getPort(hostn)
        if serverport != -1:
            hostn = hostn.split(":")[0]
        else:
            serverport = 80
	if not QUIET:
            print 'Connecting to host ' + hostn + ' with port ' + str(serverport)
        # Get file from remote server
	proxy.connect((hostn, serverport)) 
	sendMsg(header+'\r\n\r\n', proxy)
	if not QUIET:
            print 'Message sent'
	# Read the response into buffer
	resp = recvMsg(proxy)
	# Send file to client
	msgToSend = resp
	# Read file into cache if found
        if resp.split("\r\n")[0].find("200 OK") != -1:
	    writeToCache(filename, resp)
    except IOError:
        # HTTP response message for file not found
        if not QUIET:
            print "File not found"
        msgToSend = NOT_FOUND
    finally:   
        # Close the remote server socket
        proxy.close()
    return msgToSend

# handle
# Handles a request from a client
#
# clientSock: the socket connected to the client
# address: address the request came from
def handle(clientSock, address):
    if not QUIET:
        print 'Received a connection from:', address
    message = clientSock.recv(4096)
    # Make sure it's a good request, get modified headers if it is
    msgToSend = BAD_REQUEST
    header = checkRequest(message)
    if header is None:
        msgToSend = BAD_REQUEST
    elif header == "UNSUPPORTED":
        msgToSend = UNSUPPORTED 
    else:
        # Extract the filename from the given message 
        filename = getFilename(header)
        if filename is not None:
            if not QUIET:
                print 'Using filename: ' + filename
            # Check the cache
            data = checkCache(filename)
        else:
            data = None
        if data is not None:
            # ProxyServer finds a cache hit and generates a response message
            msgToSend = data
            if not QUIET:
                print 'Read from cache'
        # File not found in cache
        else:
            msgToSend = getFromServer(header, filename)
    # send message
    sendMsg(msgToSend, clientSock)
    clientSock.shutdown(0)
    clientSock.close()

try:
    if sys.argv[1] != "-q":
        port = int(sys.argv[1])
        QUIET = False
    else:
        port = int(sys.argv[2])
        QUIET = True
except:
    print 'Usage : "./pa1-final.py [-q] port"\n[port: the port to bind the proxy server to]'
    sys.exit(2)

# Create a server socket, bind it to a port and start listening
tcpSerSock = socket(AF_INET, SOCK_STREAM)
tcpSerSock.bind(('', port))
tcpSerSock.listen(100)

while 1:
    try:
        # Start receiving data from the client
        if not QUIET:
            print 'Ready to serve...'
        tcpCliSock, addr = tcpSerSock.accept()
        thread.start_new_thread(handle, (tcpCliSock, addr))
    except KeyboardInterrupt:
        if not QUIET:
            print 'Shutting server down...'
        tcpSerSock.shutdown(0)
        tcpSerSock.close()
        sys.exit(0)
