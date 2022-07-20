# Space Pirate:Entrypoint

### Challenge: PWN

### Tools: Ghidra, Pwndbg

### Vulnerability: Format String

This challenge is in the form of a format string  vulnerability. Since I had never used one I followed these links for a very good run down on a format string attack.

https://kevinalmansa.github.io/application%20security/Format-Strings

[infosec](https://infosecwriteups.com/exploiting-format-string-vulnerability-97e3d588da1b)

Below is the main function where our vulnerability sits. The check_pass function has no actual vulnerability.
