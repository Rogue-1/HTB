### Challenge: Lost Modulus

### Type: Crypto


We get 2 files, a python script and an output file containing our encrypted flag.

From the python script we can see it is being encrypted using p,q,e,n,d.

The e is very small indicating a low public exponent attack. https://en.wikipedia.org/wiki/Coppersmith%27s_attack

We also see in the def encrypt that pt= int(data.hex(),16) meaning the data is getting converted to hex by 16 before being encrypted.

This is where we can start the decrypt it.

Originally I tried to reverse engineer the code and find the values of each of the self() but the true method was far simpler.

Note: This link contains useful information on decrypting RSA https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Decryption


```python
#!/usr/bin/python3
from Cryptodome.Util.number import getPrime, long_to_bytes, inverse
flag = open('flag.txt', 'r').read().strip().encode()

class RSA:
    def __init__(self):
        self.p = getPrime(512)
        self.q = getPrime(512)
        self.e = 3
        self.n = self.p * self.q
        self.d = inverse(self.e, (self.p-1)*(self.q-1))
    def encrypt(self, data: bytes) -> bytes:
        pt = int(data.hex(), 16)
        ct = pow(pt, self.e, self.n)
        return long_to_bytes(ct)
    def decrypt(self, data: bytes) -> bytes:
        ct = int(data.hex(), 16)
        pt = pow(ct, self.d, self.n)
        return long_to_bytes(pt)

def main():
    crypto = RSA()
    print ('Flag:', crypto.encrypt(flag).hex())

if __name__ == '__main__':
    main()
```

```
Flag: 05c61636499a82088bf4388203a93e67bf046f8c49f62857681ec9aaaa40b4772933e0abc83e938c84ff8e67e5ad85bd6eca167585b0cc03eb1333b1b1462d9d7c25f44e53bcb568f0f05219c0147f7dc3cbad45dec2f34f0
```

First we are going to change the flag from hex to integer giving us ```780865154948750571515875825956842965597268480061942498223759415931178548538528991182487495101556011494286950683286512165475038389107892269787484651054279065941410737793736223804092347531386151065849807188034668245557897119294115024094420977925386642701753372658008076601701```

```python
# hex string to int
hex_str = (b'0x05c61636499a82088bf4388203a93e67bf046f8c49f62857681ec9aaaa40b4772933e0abc83e938c84ff8e67e5ad85bd6eca167585b0cc03eb1333b1b1462d9d7c25f44e53bcb568f0f05219c0147f7dc3cbad45dec2f34f03bcadcbba866dd0c566035c8122d68255ada7d18954ad604965')
# hex to int
num = int(hex_str, 16)
print(num)
```

Now if we plug that into factordb.com we can get our new integer of ```9208566198168854769137135900129825812636831889153009607082441577495048346488797274341323901```

![image](https://user-images.githubusercontent.com/105310322/189981376-19f85121-2907-4394-a215-472a18bec7d6.png)

![image](https://user-images.githubusercontent.com/105310322/189982178-9d2ae3f1-7b12-4633-8a88-87114d638fa3.png)

![image](https://user-images.githubusercontent.com/105310322/189982254-f1aaf942-ea3f-421c-a30a-b2abc61c4529.png)

Now we just convert the integer to ascii and we get our flag!

```python
from Cryptodome.Util.number import long_to_bytes
long_to_bytes(b'9208566198168854769137135900129825812636831889153009607082441577495048346488797274341323901')
print(long_to_bytes(9208566198168854769137135900129825812636831889153009607082441577495048346488797274341323901))
```
```b'HTB{n3v3r_us3_sm4ll_3xp0n3n7s_f0r_rs4}'```

Still considered an easy challenge but I am not a Crypto kind of person and I had to learn alot about RSA.


This person has a really informative video on this exact challenge that helped me learn about the attack ```https://www.youtube.com/watch?v=FtYRVbAg_0U&t=5s```
