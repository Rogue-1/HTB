# Rebuilding

### Challenge: Reverse Engineering

### Tools: Ghidra, Python, Xor decoder/Cyberchef

Running ./rebuilding shows preparing secret keys and missing required argument.

```console
(base) ┌──(rogue1㉿rogue1)-[~/HTB/CTF/Apocalypse2022/rev_rebuilding]
└─$ ./rebuilding                                 
Preparing secret keys
Missing required argument
```


So before going further with that, I went into Ghidra to further debug the program.

```cs
undefined8 main(int param_1,long param_2)

{
  int __c;
  size_t sVar1;
  undefined8 uVar2;
  int local_14;
  int local_10;
  int local_c;
  
  if (param_1 != 2) {
    puts("Missing required argument");
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  local_14 = 0;
  sVar1 = strlen(*(char **)(param_2 + 8));
  if (sVar1 == 0x20) {
    for (local_10 = 0; local_10 < 0x20; local_10 = local_10 + 1) {
      printf("\rCalculating");
      for (local_c = 0; local_c < 6; local_c = local_c + 1) {
        if (local_c == local_10 % 6) {
          __c = 0x2e;
        }
        else {
          __c = 0x20;
        }
        putchar(__c);
      }
      fflush(stdout);
      local_14 = local_14 +
                 (uint)((byte)(encrypted[local_10] ^ key[local_10 % 6]) ==
                       *(byte *)((long)local_10 + *(long *)(param_2 + 8)));
      usleep(200000);
    }
    puts("");
    if (local_14 == 0x20) {
      puts("The password is correct");
      uVar2 = 0;
    }
    else {
      puts("The password is incorrect");
      uVar2 = 0xffffffff;
    }
  }
  else {
    puts("Password length is incorrect");
    uVar2 = 0xffffffff;
  }
  return uVar2;
}
```



The missing required argument seen earlier was from not inputting a password. So if we run (./rebuilding password) now we can see what happens.
~~~console
(base) ┌──(rogue1㉿rogue1)-[~/HTB/CTF/Apocalypse2022/rev_rebuilding]
└─$ ./rebuilding password                        
Preparing secret keys
Password length is incorrect
~~~                               
We now get preparing secret keys and password length is incorrect.
If we look at the ghidras main function we can see on line 32 is says if 
~~~cs
( local_14 == 32 )
~~~
puts (“The password is correct”)

This means that the length of the password needs to be 32 characters in length. Great, now we just need to find the password.

Going to Ghidra instead we use the same decompiler of the main function and double click on encrypted to take us to some interesting hexidecimals.
~~~yml
                             encrypted                                       XREF[3]:     Entry Point(*), main:00100964(*), 
                                                                                          main:0010096b(R)  
        00301020 29 38 2b        undefine
                 1e 06 42 
                 05 5d 07 
           00301020 29              undefined129h                     [0]                               XREF[3]:     Entry Point(*), main:00100964(*), 
                                                                                                                     main:0010096b(R)  
           00301021 38              undefined138h                     [1]
           00301022 2b              undefined12Bh                     [2]
           00301023 1e              undefined11Eh                     [3]
           00301024 06              undefined106h                     [4]
           00301025 42              undefined142h                     [5]
           00301026 05              undefined105h                     [6]
           00301027 5d              undefined15Dh                     [7]
           00301028 07              undefined107h                     [8]
           00301029 02              undefined102h                     [9]
           0030102a 31              undefined131h                     [10]
           0030102b 10              undefined110h                     [11]
           0030102c 51              undefined151h                     [12]
           0030102d 08              undefined108h                     [13]
           0030102e 5a              undefined15Ah                     [14]
           0030102f 16              undefined116h                     [15]
           00301030 31              undefined131h                     [16]
           00301031 42              undefined142h                     [17]
           00301032 0f              undefined10Fh                     [18]
           00301033 33              undefined133h                     [19]
           00301034 0a              undefined10Ah                     [20]
           00301035 55              undefined155h                     [21]
           00301036 00              undefined100h                     [22]
           00301037 00              undefined100h                     [23]
           00301038 15              undefined115h                     [24]
           00301039 1e              undefined11Eh                     [25]
           0030103a 1c              undefined11Ch                     [26]
           0030103b 06              undefined106h                     [27]
           0030103c 1a              undefined11Ah                     [28]
           0030103d 43              undefined143h                     [29]
           0030103e 13              undefined113h                     [30]
           0030103f 59              undefined159h                     [31]
           00301040 14              undefined114h                     [32]
           00301041 00              undefined100h                     [33]
~~~

We can see [0] - [32] with hexidecimals to compliment them. The 32 in length earlier reveals that this is our password, but it’s encrypted. Converting these to various different formats did not provide any possible passwords because we are missing the key.

In the picture below a key is revealed.
~~~yml
                             s_umans_00301043                                XREF[4,5]:   Entry Point(*), 
                             s_mans_00301044                                              _INIT_1:0010085a(W), 
                             s_ans_00301045                                               main:00100991(*), 
                             s_ns_00301046                                                main:00100998(R), 
                             s_s_00301047                                                 _INIT_1:00100861(W), 
                             key                                                          _INIT_1:00100868(W), 
                                                                                          _INIT_1:0010086f(W), 
                                                                                          _INIT_1:00100876(W), 
                                                                                          _INIT_1:0010087d(W)  
        00301042 68 75 6d        ds         "humans"
                 61 6e 73 00
~~~

At first I believed the key was humans but upon further inspection I found that in the function _INIT_1 that the real key was aliens.

~~~cs
void _INIT_1(void)

{
  puts("Preparing secret keys");
  key[0] = 'a';
  key[1] = 'l';
  key[2] = 'i';
  key[3] = 'e';
  key[4] = 'n';
  key[5] = 's';
  return;
}
~~~


We are nearly done, we just have to decode the hexidecimal with the key

I did this with 2 different methods. Python and the XOR Cipher website.

~~~python
#!/usr/bin/python3
from itertools import cycle
def xor():    
    key = "aliens"
    hex_array = [0x29, 0x38, 0x2b, 0x1e, 0x06, 0x42, 0x05, 0x5d, 0x07, 0x02, 0x31, 0x42, 0x0f, 0x33, 0x0a, 0x55, 0x00, 0x00, 0x15, 0x1e, 0x1c, 0x06, 0x1a, 0x43, 0x13, 0x59, 0x36, 0x54, 0x00, 0x42, 0x15, 0x11]
    temp = ""
    for i in hex_array:
        temp += chr(i)
    flag = ''.join(chr(ord(c)^ord(k)) for c,k in zip(temp, cycle(key)))
    print(flag)

def main():
    xor()

if __name__ == "__main__":
    main()
~~~
~~~console
(base) ┌──(rogue1㉿rogue1)-[~/HTB/CTF/Apocalypse2022/rev_rebuilding]
└─$ python3 flag.py    
HTB{h1d1ng_1n_c0nstruct0r5_1n1t}
~~~
![image](https://user-images.githubusercontent.com/105310322/180051858-3375fb2b-829e-4bf9-a1e9-27e11a80dc50.png)

