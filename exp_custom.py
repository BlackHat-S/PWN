# coding=utf-8
from pwn import *
import time
context.terminal = ['tmux', 'split','-h']
context.log_level = 'debug'

def z(a=''):
    if debug:
        gdb.attach(p,a)
    if a == '':
  	    raw_input()

arch="amd64"  #arch="amd64"

debug=1
if debug:
    p=process('./NameSystem')
    #e=ELF('./ezshellcode')
    proc_base = p.libs()[p.cwd + p.argv[0].strip('.')]                   #获取本地程序加载基地址
    if arch=="i386":
        libc_base = p.libs()["/lib/i386-linux-gnu/libc-2.23.so"]            #获取本地libc加载基地址
    elif arch=="amd64":
        libc_base = p.libs()["/lib/x86_64-linux-gnu/libc-2.23.so"]

    

else:
    p=remote('129.211.58.26',10000)
    #p.sendline("zmbcen")

def add_note(size,content):
    p.recvuntil("Your choice :")
    p.sendline("1")
    p.recvuntil("Size:")
    p.sendline(str(size))
    p.recvuntil("Name:")
    p.sendline(content)


def delete_note(index):
    p.recvuntil("Your choice :")
    p.sendline("3")
    p.recvuntil("Input the Note:")
    p.sendline(content)

def my_quit():
    p.recvuntil("Your choice :")
    p.sendline("4")

my_quit()
p.interactive()
