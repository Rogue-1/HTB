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




By inputting a couple of %p we can see that the address 0xdeadbeef is at offset 6 and input data is put into offset 7. Anything after becomes arbitrary.


So now that we know where we need to point the format string attack we can set up the command. Also we only need to change the last 2 bytes for the attack

Command = %4919c%7$hn	
	- 1337=4919(last 4 of dead1337 from hex) 
  - c= prints character
  - %7=the offset we are placing the $hn 
  - $hn=writes 4 bytes to the target pointer.






With that we have our flag!

When I first started out I think I was diving too deep and trying scripts like `“dead1337””\x20\xdf\xff\xff””%7$n”` to print the flag but eventually realized this challenge was simpler than that.

