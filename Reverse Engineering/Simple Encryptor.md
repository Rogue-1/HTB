# Impossible Password

### Challenge: Reverse Engineering

### Tools: Ghidra, Cyberchef, C

### Files: encrypt, flag.enc

### Description:On our regular checkups of our secret flag storage server we found out that we were hit by ransomware! The original flag data is nowhere to be found, but luckily we not only have the encrypted file but also the encryption program itself.

For starters I did not solve this challenge without a lot of help from some good people, this write up will be more for learning and record keeping.

This challenge is listed as very easy but for me it was harder than most that I have completed.



In Ghidra we have the main function that reads from a flag file and then encrypts each byte twice. 1st by Xoring and 2nd by ROL(Rotating Left). For a long time I read it as Rotating right and bit shifting right but neither of those options were getting me anywhere. After that it gets written to a file. At the first fwrite function it writes 4 bytes and the second fwrite function writes 28 bytes to the flag.enc.

```cs
undefined8 main(void)

{
  int iVar1;
  time_t tVar2;
  long in_FS_OFFSET;
  uint local_40;
  uint local_3c;
  long local_38;
  FILE *local_30;
  size_t local_28;
  void *local_20;
  FILE *local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_30 = fopen("flag","rb");
  fseek(local_30,0,2);
  local_28 = ftell(local_30);
  fseek(local_30,0,0);
  local_20 = malloc(local_28);
  fread(local_20,local_28,1,local_30);
  fclose(local_30);
  tVar2 = time((time_t *)0x0);
  local_40 = (uint)tVar2;
  srand(local_40);
  for (local_38 = 0; local_38 < (long)local_28; local_38 = local_38 + 1) {
    iVar1 = rand();
    *(byte *)((long)local_20 + local_38) = *(byte *)((long)local_20 + local_38) ^ (byte)iVar1;
    local_3c = rand();
    local_3c = local_3c & 7;
    *(byte *)((long)local_20 + local_38) =
         *(byte *)((long)local_20 + local_38) << (sbyte)local_3c |
         *(byte *)((long)local_20 + local_38) >> 8 - (sbyte)local_3c;
  }
  local_18 = fopen("flag.enc","wb");
  fwrite(&local_40,1,4,local_18);
  fwrite(local_20,1,local_28,local_18);
  fclose(local_18);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```
So we are going to make a flag file and fill it with whatever just to show the next example.
Now if we go into GDB we can see the seed by setting a breakpoint in the main function right on the srand call.

```console
   0x55555555532f <main+166>    mov    edi, 0
   0x555555555334 <main+171>    call   time@plt                <time@plt>
 
   0x555555555339 <main+176>    mov    dword ptr [rbp - 0x38], eax
   0x55555555533c <main+179>    mov    eax, dword ptr [rbp - 0x38]
   0x55555555533f <main+182>    mov    edi, eax
 ► 0x555555555341 <main+184>    call   srand@plt                <srand@plt>
        seed: 0x62eac962
 
   0x555555555346 <main+189>    mov    qword ptr [rbp - 0x30], 0
   0x55555555534e <main+197>    jmp    main+311                <main+311>
 
   0x555555555350 <main+199>    call   rand@plt                <rand@plt>
 
   0x555555555355 <main+204>    movzx  ecx, al
   0x555555555358 <main+207>    mov    rdx, qword ptr [rbp - 0x30]
───────────────────────────────────[ STACK ]────────────────────────────────────
00:0000│ rsp 0x7fffffffdf10 —▸ 0x7fffffffdf37 ◂— 0x55555555989000
01:0008│     0x7fffffffdf18 ◂— 0x555562eac962
02:0010│     0x7fffffffdf20 ◂— 0x0
03:0018│     0x7fffffffdf28 —▸ 0x5555555592a0 ◂— 0x0
04:0020│     0x7fffffffdf30 ◂— 0x32 /* '2' */
05:0028│     0x7fffffffdf38 —▸ 0x555555559890 ◂— 'Whatisthemeaningoflife'
06:0030│     0x7fffffffdf40 —▸ 0x7fffffffe040 ◂— 0x1
07:0038│     0x7fffffffdf48 ◂— 0x7da2f75aca81f100
─────────────────────────────────[ BACKTRACE ]──────────────────────────────────
 ► f 0   0x555555555341 main+184
   f 1   0x7ffff7e0cd0a __libc_start_main+234
────────────────────────────────────────────────────────────────────────────────
pwndbg> 
```
And this seed "0x62eac962" is actually our 1st 4 bytes being written to flag.enc. The thing about seeds and PRNG is that if you know the seed then you can always get the same output. Meaning if we reverse ./encrypt to be ./decrypt we can get our flag.

```console
└──╼ [★]$ xxd flag.enc
00000000: 62c9 ea62 68ae b5b7 982d ec07 6cd0 79cf  b..bh....-..l.y.
00000010: d1e9 1364 e030 67c9 8586 1a71 3e0d 3d8a  ...d.0g....q>.=.
00000020: 02ba 3fb7 dd78 06f9 b5ce ad9f 4f8e 3006  ..?..x......O.0.
00000030: b4fd b29c 4633 
```

So since the flag was encrypted by XOR then ROL we need to do the opposite to decrypt it. ROR then XOR. This is where I spent most of my time trying to get C to run properly but I am not that fluent quite yet. So I used a lot of cyberchef to try and ROL or ROR, then XOR but I wasnt having much luck with it. I even tried a python script for XORshifting which I am still pretty interested in as this was almost the same thing.

###Without further adieu I present the script that taught me a lot and helped me achieve the flag. Again I did not write this script and I would not have solved this challenge without its help. Even all of the comments were written by another person.

From what I learned, if you make this script in python it will not output the same due to how C and Python have different RNG algorithyms.


```cs
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

//* I imported GLIBC 2.2.5 because I was unsure about different algorithms between different versions of libc *//
__asm__(".symver realpath,realpath@GLIBC_2.2.5");  



int main()
{
    
    int size = 29; // 32-4 = 28, but c needs an end of line char at the end of a string
    FILE *fp; //File pointer
    fp = fopen("flag.enc", "rb"); // opening file with readbytes (rb)
    /* This was the line which made so much trouble, because "char flag[size];" cuts off the first bit..."uint8_t flag[size]" does not */
    uint8_t flag[size]; 
    flag[28] = '\0'; // end of line char
    int seed; 
    fread(&seed, 4, 1, fp); // fread(var, length of element(4 bytes = integer), elements=1, file pointer) reads seed
    fread(&flag, 1, 28, fp); // fread(var, length of element(1 bytes = uint8_t), elements=28, file pointer) reads encrypted flag
    srand(seed); //sets seed of random numbers
    long i;
    for(i = 0; i < size-1; i++){
    	uint8_t rand1 = rand(); // get first random number and convert to uint8_t (1byte)
    	uint8_t rand2 = rand() & 7; // get second random number and convert to uint8_t (1byte) and perform AND 7
        /* Because it rolled after xored you have to rol and den xor */
  	uint8_t x = flag[i]>>rand2 | flag[i]<<8-rand2; // rols to the right
    	char c = x ^ (rand1); // XOR 
	flag[i] = c;
    }
    printf("---------START OF FLAG---------\n");
    printf("%s\n",flag);
    printf("----------END OF FLAG----------\n");
    fclose(fp);
}
```


So with this script make sure the flag.enc file is the original since it may have been overwritten by a previous run of the encrypt program.



Take and save script as whatever you want.
gcc decrypt.c -o decrypt
./decrypt

```console
└──╼ [★]$ ./decrypt 
---------START OF FLAG---------
HTB{vRy_s1MplE_F1LE3nCryp0r}
----------END OF FLAG----------
```

Congratulations! In my opinion this challenge should not have been labled as very easy unless there was another simpler method I didnt see. This takes a deeper understanding of C than most of the challenges I have completed in the very easy and easy categories. As well as having to script to decrypt. Normally I could have at least run this through cyberchef a few different ways, but cyberchef isnt perfect either.

Be sure to read the scripts comments as they have alot of knowledge in them and explains very well what is going on.
