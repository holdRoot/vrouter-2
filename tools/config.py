#~!/usr/bin/env python2.7

import socket
import sys

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(sys.argv[1])

#		("server_ip", "4s", '\x00' * 4),
#		("range_start", "4s", '\x00' * 4),
#		("range_end", "4s", '\x00' * 4),
#		("netmask", "4s", '\x00' * 4),
#		("dns1", "4s", '\x00' * 4),
#		("dns2", "4s", '\x00' * 4),
#		("broadcast_ip", "4s", '\x00' * 4),
#		("server_mac", "16s", '\x00' * 6),
#		("domain_name", "32s", '\x00' * 4),

config_str = str(0) + "\xc0\xa8\x01\x01\xc0\xa8\x01\x09\xc0\xa8\x01\x80\xff\xff\xff\x00\x08\x08\x08\x08\x08\x08\x04\x04\xc0\xa8\x01\xfe\xde\xad\xbe\xef\x00\x00" + ("s" * 32)
sock.send(config_str)
print sock.recv(1024)
