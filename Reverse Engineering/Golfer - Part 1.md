# Golfer - Part 1

### Challenge: Reverse Engineering

### Tools: Ghidra, Cyberchef

### Description: A friend gave you an odd executable file, in fact it is very tiny for a simple ELF, what secret can this file hide?

We are given a tiny ELF file and not a whole lot going on. I found that GDB couldnt run it, Executing the file didnt work, My go to Ghidra didnt want to decompile it well. So I used cutter instead to try and debug it and I was able to get the flag. (ignore the "nop", I was trying to bypass the exite function so the program could call the functions but this was not the way.")


```cs
entry0 ();
0x0800004c      nop
0x0800004d      nop
0x0800004e      nop
0x0800004f      nop
0x08000050      nop
0x08000051      inc bl
0x08000053      inc dl
0x08000055      mov ecx, 0x800000a
0x0800005a      call fcn.0800012f
0x0800005f      mov ecx, 0x8000008
0x08000064      call fcn.0800012f
0x08000069      mov ecx, 0x8000024 ; '$'
0x0800006e      call fcn.0800012f
0x08000073      mov ecx, 0x800000e
0x08000078      call fcn.0800012f
0x0800007d      mov ecx, 0x800000c
0x08000082      call fcn.0800012f
0x08000087      mov ecx, 0x8000023 ; '#'
0x0800008c      call fcn.0800012f
0x08000091      mov ecx, 0x8000009
0x08000096      call fcn.0800012f
0x0800009b      mov ecx, 0x8000021 ; '!'
0x080000a5      mov ecx, 0x8000006
0x080000aa      call fcn.0800012f
0x080000af      mov ecx, 0x800000d
0x080000b4      call fcn.0800012f
0x080000b9      mov ecx, 0x8000022 ; '"'
0x080000be      call fcn.0800012f
0x080000c3      mov ecx, 0x8000021 ; '!'
0x080000c8      call fcn.0800012f
0x080000cd      mov ecx, 0x8000005
0x080000d2      call fcn.0800012f
0x080000d7      mov ecx, 0x8000021 ; '!'
0x080000dc      call fcn.0800012f
0x080000e1      mov ecx, 0x8000020 ; ' '
0x080000e6      call fcn.0800012f
0x080000eb      mov ecx, 0x8000023 ; '#'
0x080000f0      call fcn.0800012f
0x080000f5      mov ecx, 0x800000f
0x080000fa      call fcn.0800012f
0x080000ff      mov ecx, 0x8000007
0x08000104      call fcn.0800012f
0x08000109      mov ecx, 0x8000022 ; '"'
0x0800010e      call fcn.0800012f
0x08000113      mov ecx, 0x8000025 ; '%'
0x08000118      call fcn.0800012f
0x0800011d      mov ecx, 0x800000b
0x08000122      call fcn.0800012f
├ (loc) loc.08000127 ();
0x08000127      xor al, al
0x08000129      inc al
0x0800012b      mov bl, 0x2a       ; '*' ; 42
0x0800012d      int 0x80
fcn.0800012f ();
0x0800012f      push ebp
0x08000130      mov ebp, esp
0x08000132      mov al, 4
0x08000134      int 0x80
0x08000136      leave
0x08000137      ret
```

![image](https://user-images.githubusercontent.com/105310322/182474806-697f16eb-6cae-46db-b362-6566fb58ca66.png)



The reason Cutter worked for me is that its hexdump section put it together nicely that I could take the data that the call functions were using and cross reference it to the hexdump.

For example 0x80000a was in the 0x0a location of the hexdump that equals H.

So when we decode it we get
```console
0a      H
08      T
24      B
0e      {
0c      y
23      0
09      U
21      _
06      4
0d      R
22      3
21      _
05      a
21      _
20      g
23      0
0f      l
07      f
22      3
25      r
0b      }
```

HTB{y0U_4R3_a_g0lf3r}
