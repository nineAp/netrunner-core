import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((sys.argv[1], int(sys.argv[2])))
while True:
    d, a = s.recvfrom(2000); s.sendto(d, a)
