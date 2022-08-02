# Impossible Password

### Challenge: Reverse Engineering

### Tools: Ghidra, Python, Xor decoder/Cyberchef

### Description: Are you able to cheat me and get the flag?

Running the program we can see that it is checking for some input. So lets go into Ghidra and see what we can find for that spot.

```console
chmod 777 impossible_password.bin 
─[us-dedivip-1]─[10.10.14.93]─[htb-0xrogue@pwnbox-base]─[~/Downloads]
└──╼ [★]$ ./impossible_password.bin 
* sadasd
```

Scrolling through Ghidra there are alot of undefined functions but 1 stands out.
We can see that "SuperSekretKey" looks interesting so lets try that in the terminal.

```cs
void FUN_0040085d(void)

{
  int iVar1;
  char *__s2;
  byte local_48;
  undefined local_47;
  undefined local_46;
  undefined local_45;
  undefined local_44;
  undefined local_43;
  undefined local_42;
  undefined local_41;
  undefined local_40;
  undefined local_3f;
  undefined local_3e;
  undefined local_3d;
  undefined local_3c;
  undefined local_3b;
  undefined local_3a;
  undefined local_39;
  undefined local_38;
  undefined local_37;
  undefined local_36;
  undefined local_35;
  char local_28 [20];
  int local_14;
  char *local_10;
  
  local_10 = "SuperSeKretKey";
  local_48 = 0x41;
  local_47 = 0x5d;
  local_46 = 0x4b;
  local_45 = 0x72;
  local_44 = 0x3d;
  local_43 = 0x39;
  local_42 = 0x6b;
  local_41 = 0x30;
  local_40 = 0x3d;
  local_3f = 0x30;
  local_3e = 0x6f;
  local_3d = 0x30;
  local_3c = 0x3b;
  local_3b = 0x6b;
  local_3a = 0x31;
  local_39 = 0x3f;
  local_38 = 0x6b;
  local_37 = 0x38;
  local_36 = 0x31;
  local_35 = 0x74;
  printf("* ");
  __isoc99_scanf(&DAT_00400a82,local_28);
  printf("[%s]\n",local_28);
  local_14 = strcmp(local_28,local_10);
  if (local_14 != 0) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  printf("** ");
  __isoc99_scanf(&DAT_00400a82,local_28);
  __s2 = (char *)FUN_0040078d(0x14);
  iVar1 = strcmp(local_28,__s2);
  if (iVar1 == 0) {
    FUN_00400978(&local_48);
  }
  return;
}
```

Awesome but now we have another input that is needed.

```console
./impossible_password.bin 
* SuperSeKretKey
[SuperSeKretKey]
** 
```

If we go to the function after the "SuperSekretKey" we find that the bytes are being xored. It just so happens that the string of hex beneath "SuperSekretKey" looked pretty special.

```cs

void FUN_00400978(byte *param_1)

{
  int local_14;
  byte *local_10;
  
  local_14 = 0;
  local_10 = param_1;
  while ((*local_10 != 9 && (local_14 < 0x14))) {
    putchar((int)(char)(*local_10 ^ 9));
    local_10 = local_10 + 1;
    local_14 = local_14 + 1;
  }
  putchar(10);
  return;
}
```

So if we go into CyberChef and convert the hexidecimal to ASCII (A]Kr=9k0=0o0;k1?k81t)

and then XOR it by 9 it will give us the flag!

HTB{40b949f92b86b18}


GG
