# kitctfctf-2022
This repo contains the solve scripts and a few notes for most of my challenges for KITCTFCTF 2022.
The challenges are also archived here: https://2022.ctf.kitctf.de/.
The remote server for all of my challenges is still running as well and probably will be for the foreseeable future.

## croc

croc was a lambda calculus "executor" written in C++ and contained a lexer, parser and an interpreter that performed the Alpha-/BetaConversions. 
The ``croc/input`` file contains the lambda calculus "program" with replaced symbols.  

```
"🐊" => "λ"  
"💀" => "."  
"🤓" => "("  
"😳" => ")"  
```

The cleaned up and converted program can be found in the ``croc/cleaned_up_program`` file.
The 24-digit code, that was supposed to be found, was converted to church numbers (e.g. ZERO = "λa. (λb. b)", ONE = "λa. a", TWO = succ ONE, ...) and given as an input to the top-level function of the lambda calculus program. After that, reductions are performed according to the [rules](https://en.wikipedia.org/wiki/Lambda_calculus) of standard untyped lambda calculus.  
In the end, after no more reductions can be performed, the given code is accepted if the resulting expression was reduced to a TRUE in lambda calculus (TRUE = "λa. (λb. a)") and rejected otherwise. 


### The program
The topmost function accepts 24 parameters (transformed digits of the code). For each parameter ``x / 2`` and ``x % 2`` are computed and the results are compared to a fixed value. This comparison is always in the form of ``(a - b) == 0 && (b - a) == 0`` where a and b are checked for equality. This has to be done because we did not introduce signed numbers here (e.g. (a - b) == 0 holds for every a, b where a <= b).  
Extracting the constant values for the div/mod results will let us compute the expected parameter value and therefore the whole 24-digit code!  
On top of those checks, multiple blocks of four parameters each are added and compared against another constant value. However, those can be ignored as the correct code can already be extracted with the div/mod results.

``solve.py`` transforms the input to an AST, converts it to a more readable form (see  ``croc/cleaned_up_program``) and extracts the 24-digit solution automatically. 


## Date
I wrote a detailed writeup that can be found on my website [https://blog.ju256.de/posts/kitctfctf22-date/](https://blog.ju256.de/posts/kitctfctf22-date/).


## HolyZIII

HolyZII was an AOT compiled HolyC binary. It can be executed from within TempleOS with the statement ``Load("HolyZIII.BIN");``.  
Apart from that, the binary resembles a somewhat standard crackme.  
The key consists of 32 printable ASCII characters. The first 16 of those are verified with different arithmetic operations. 
For every byte of the first half of the key, a function is called that verifies a byte from the second half by performing a simple xor and comparing the result against a fixed value. The following pseudocode illustrates this.

```python
def FUNC_0(key):
	return key[25] ^ 239 == 16

...

def FUNC_254(key):
	return key[28] ^ 220 == 225

def FUNC_255(key):
	return key[25] ^ 186 == 186


FUNC_ARRAY = [FUNC_0, ..., FUNC_254, FUNC_255]

# verification of the first 16 bytes ...

result = 0
for kbyte in key[:16]:
    if FUNC_ARRAY[kbyte](key):
    	result += 1
if result == 16:
	accept()
else:
	fail()
```

The index, xor value and the comparison value for each function can be extracted with an IDAPython script (``holyziii/ida_get_func_params.py``) which is also included here.
``holyziii/solve.py`` combines all of this and extracts the correct key using z3.

## movsh

movsh allowed us to execute arbitary shellcode as long as it satisfies two constraints. Only mov instructions were allowed with the exception of two syscall instructions. Syscalls were also restricted to open, read, write, exit.
Before the shellcode is executed, a mov eax, 0x3c; syscall; (call to exit) is appended to the shellcode we provided. However, the exit code that will be returned is not set. We can use this to leak one byte of the flag at a time with shellcode performing something like this:
```asm
fd = open("flag.txt")
read(fd, stack, 0x100)

mov rdi, [current_flag_byte_pointer]
```
See ``movsh/expl.py`` for the full solve script.  

There is also a nice proper [writeup](https://github.com/nobodyisnobody/write-ups/tree/main/KITCTFCTF.2022/pwn/movsh) by nobodyisnobody which also covers a neat unintended solution.

## SYS_jail

SYS_jail was a linux kernel challenge where you had to exploit a newly introduced, custom syscall called SYS_jail. Upon connection, the challenge server executes a wrapper which will just perform the SYS_jail syscall and drop us into a shell. The only interesting part about the provided patch for this syscall is its actual implementation in the do_jail function:

```patch
+int do_jail(struct jail_info *info) {
+	unsigned int uid;
+	unsigned long long token;
+	kuid_t kuid;
+	kgid_t kgid;
+	struct cred *new_cred;
+
+	uid = get_current_user()->uid.val;
+	token = 0;
+
+
+	if (info->requested_uid == -1) {
+		info->requested_uid = (get_random_u32() | 10000) & 0x7fff;
+	} else if (info->requested_uid < 10000 || info->requested_uid > 0x7fff) {
+		return -EPERM;
+	}
+
+	for (unsigned long long i = 0; i < 0xf; i++) {
+		// i don't trust get_random_u32(). use it to generate some real random bytes.
+		token ^= (((unsigned long long)get_random_u32()) << 32 | get_random_u32());
+	}
+
+	kuid = KUIDT_INIT(info->requested_uid);
+	kgid = KGIDT_INIT(info->requested_uid);
+
+	new_cred = prepare_creds();
+	if (new_cred == NULL) {
+		return -ENOMEM;
+	}
+
+	new_cred->uid = kuid;
+	new_cred->gid = kgid;
+	new_cred->euid = kuid;
+	new_cred->egid = kgid;
+	commit_creds(new_cred);
+
+	info->token = token;
+	info->requestor_uid = uid;
+
+	return 0;
+}
``` 

Executing this syscall will change current credentials of the user (uid, gid, euid and egid) to a given or random value in the range (10000, 32767). The problem here is that the user-controlled contents of the jail_info struct are not copied with a copy_from_user(). Therefore, we can exploit a classic TOCTOU bug and try to win the race between verifying the requested_uid and actually using it in the commit_creds. See sys_jail/expl.c for the full exploit code.

Note: A few people had difficulties during the CTF while transferring their exploit to the remote server. Unfortunately, I could not provide any hints while the CTF was running. I originally included the following hint about this problem in the challenge description, which I probably should have kept after all:

Transferring files (with base64 for example) to the remote is quite slow. Therefore, if you want to transfer any compiled program consider compiling with a libc that is optimized to keep the file size small (e.g. uClibc, dietlibc, etc.).


# xmalloc
For xmalloc we are given a custom heap implementation written in C (xmalloc/xfree) and a sandbox program that interacts with this heap implementation. For every allocated chunk, a random value or cookie is placed in front of it. All cookies are verified at the start of every call to xmalloc and xfree. This is supposed to be a classic overflow protection like stack cookies/canaries.
The mentioned sandbox allows us to allocate, free, edit and print chunks. The edit contains a large overflow, which is even advertised in the challenge description. 
```c
void edit() {
    u32 index;
    printf("Index: ");
    index = read_int();
    if (index < 0x20 && chunks[index] != NULL) {
        printf("Data: ");
        // I left this overflow for you. There's no way to do anything with it anyways,
        // because the heap security is to good.
        read(0, chunks[index], 0x1000);
    } else {
        puts("Invalid index");
    }
}
```
Consequently, the goal seems to be using the given overflow to bypass the overflow protection on the custom heap and get RCE.  
The second bug, next to the overflow in the edit, lies in the way a new heap is created (see ``init_main_arena()``) when the old heap is full. Cookies on this new heap will be exactly the same because the seed used to generate those cookies is not updated. 
```c
void init_main_arena(void *heap_start, CookieJar *cookie_jar) {
	xmain_arena.head_chunk = NULL;
	xmain_arena.heap_start = heap_start;
	xmain_arena.available = HEAP_SIZE;
	xmain_arena.cookie_jar = cookie_jar;
	xmain_arena.small_chunk_free_list = NULL;

	guard_head.next_free = &guard_tail;
	guard_head.prev_free = &guard_tail;
	
	guard_tail.next_free = &guard_head;
	guard_tail.prev_free = &guard_head;
	
	xmain_arena.large_chunk_free_list = &guard_head;
	srand(seed);
}
```
In addition, the validation of cookies only happens on the current heap. Therefore, after a new heap was created, we can safely overflow chunks on the old heap which we can use to leak cookies that will be reused on the new heap.
With a leaked cookie, an arbitrary read/write can be achieved by overwriting the freelist pointer of a chunk. Similarly to the libc implementation, there is a hook for xmalloc and xfree which can be overwritten for RCE.
It is also worth mentioning that the needed mmap_base leak is possible since the head of the freelist for large chunks (similar to the unsorted_bin for libc) points to the libsecureheap library.
For the details on this, please refer to the full exploit (see xmalloc/expl.py).
