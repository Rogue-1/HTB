### Challenge: oBfsC4t10n2

### Type: Forensics


Starting off we get an xls document so lets open it up and see what we find.

![image](https://user-images.githubusercontent.com/105310322/189444858-1218ad87-52a6-4343-9d50-041ff50bee67.png)

Here we do not get much but it is actually hiding "malicious" code. It is possible to reveal hidden sheets in either libre office or excel.

In the hidden sheets we find a blank page which is still obviously hiding something so if we quickly change the color formatting of the letters we can see everything it is hiding.

![image](https://user-images.githubusercontent.com/105310322/189445318-b1f2915b-a15e-450b-b978-075750de8660.png)

There is alot of info and plenty of functions ```=concatenate``` corresponding to specific cells. This is exactly how our flag is hiding. Originally I manually went through each of the functions to see what they were doing.

![image](https://user-images.githubusercontent.com/105310322/189445607-840becaa-3680-4e6e-a2f1-8ab438a34f65.png)

Basically it just downloads a file and executes a shell.

Hiding in these functions is also how it concatenates the flag.

An easy way to get most of the function answers is to just run a $strings on the file giving some good info back.

```console
MbP?_
ffffff
ffffff
GIS4
DINU"
?]{~
SMTJ
RESDLL
UniresDLL
PaperSize
LETTER
Orientation
PORTRAIT
Resolution
ResOption1
ColorMode
Color
V4DM
333333
?333333
http://0b.htb/s.dll
ShellExecuteA
http://0b
00:00:02
rstegerg3B
hTXx.dl
4.0_M4cr0s_r_b4cK}
URLDownloadToFileA
Xc3l_
c1zB0vasNO
Windows (64-bit) NT 10.00
WindowsD!
00:00:02
agawf23f
Shell32
tp://0
ShellExe
00:00:02
00:00:02
Lsl23Us7a
URLDownl
oadToFileA
LDown
4.0_M
kYKlI\U
Shell
URLDownloadToFileA
6.1D!
A$0!(rR
cuteA
rncwner\
iQhTXx.dll
C:\rncwner\Ck
adToFi
htb/s.
7.0D
Kernel32
CreateDirectoryA
C:\rncwner
Kernel32
CreateDirectoryA
C:\rncwner\CkkYKlI
0s_r_
JJCCJJ
JJCCCCJ
Open
rundll32.exeD3
URLMON
C:\rncwner\CkuiQhTXx.dll
00:00:02
00:00:02
KsshpqC4Mo
MbP?_
ffffff
ffffff
333333
?333333
Sheet1g
0xdf
0xdf
Microsoft Excel
invoice
c1zB0vasNo
Worksheets
Excel 4.0 Macros
```

Now there is alot of information but since I originally did this manually I already knew what I was looking for.

Note: With the way it was designed they did not want you doing it this way so not everything will show. Some of the =CONCATENATE functions only take a cell that has a single value.

So after going through it all with the function wizard I had came up with this.

```Xc3l_4.0_M4cr0s_r_b4cK}```

But I was still missing something :/

I realized I had forgot to go back and check an IF function that had some following =CONCATENATE functions that was hiding the rest of my flag.

```HTB{n0w_e```

Which gives us......


```HTB{n0w_eXc3l_4.0_M4cr0s_r_b4cK}```

WHOOO!

I am still surprised this was listed as hard for a forensics challenge but alot of these things are not rated correctly anyways.
