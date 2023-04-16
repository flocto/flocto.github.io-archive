---
title: "BucketCTF 2023 Megathread"
date: 2023-04-12T23:08:49-05:00
tags: ["crypto", "misc", "rev", "bucketctf", "2023"]
summary: Megathread for BucketCTF 2023, with writeups for the challenges I solved.
mathjax: true
---

Originally I was going to play alone but got drafted by my team so I ended up playing with them :joy:. Still, we ended up 6th place, could be better if we weren't also focusing MidnightSun and CursedCTF at the same time.

Here's a collection of writeups for most of the challenges I solved. I'm making a seperate post for the Java Random ones, so expect that later as well.

---
# TOC
| Table of Contents |
| ----------- 
| [Misc](#misc) |
| - [minecraft](#minecraft---200---easy) |
| - [Image-2](#image-2---200---easy) |
| - [Detective](#detective---200---easy) |
| - [Transmission](#transmission---278---easy) |
| - [clocks](#clocks---366---medium) |
| - [Minecraft 2](#minecraft-2---398---easy) |
| - [Clocks 2](#clocks-2---408---hard) |
| - [Drawing](#drawing---456---easy) |
| - [Secret Bucket](#secret-bucket---492---medium) |
| [Crypto](#crypto) |
| - [Search-0](#search-0---380---easy) |
| - [Search-1](#search-1---390---medium) |
| - [Search-2](#search-2---422---medium) |
| - [Search-3](#search-3---470---hard) |
| - [Rotund Bits](#rotund-bits---474---easy) |
| - [SCAlloped potatoes](#scalloped_potatoes---484---medium) |
| [Reversing](#rev) |
| - [Troll](#troll---464---hard) |

---

## Misc
My favorite category, picked up 3 first bloods here too.
I'll go in point order because I forgot what order I originally solved them.

### minecraft - 200 - Easy
> I just started playing minecraft for my computer science class and forgot to remove a sign with my password before exiting the world. Could you please check what my password is.
> 
> [https://storage.ebucket.dev/bucketctfMC.mcworld](https://storage.ebucket.dev/bucketctfMC.mcworld)

A `.mcworld` file is just a zip file containing the files used to store all information about a Minecraft world, so let's extract that first. We get the resulting `level.dat`, `level_old.dat`, `levelname.txt`, and so on.

Though `level.dat` technically contains the sign, I couldn't open it in NBTViewer for some reason, so we can't extract it that way. Thankfully, we're given a log file in `db/000003.log`. It should store the sign in plaintext, so we're good to go.

```terminal
$ strings db/000003.log | grep "bucket" -A 2 -B 2
SignTextColor
Text&
bucket{1L0V3MIN
3CRAFT_1c330e9
105f1}
--
SignTextColor
Text&
bucket{1L0V3MIN
3CRAFT_1c330e9
105f1}
--
SignTextColor
Text&
bucket{1L0V3MIN
3CRAFT_1c330e9
105f1}
```
flag: `bucket{1L0V3MIN3CRAFT_1c330e9105f1}`

[Back to TOC](#toc)

### Image-2 - 200 - Easy
> You can almost see the flag.
> 
>[https://storage.ebucket.dev/mrxbox98.png](https://storage.ebucket.dev/mrxbox98.png)

Just strings.
```terminal
$ strings -n 10 mrxbox98.png
bucket(m3t4d4t4_4c53f444)
```

### Detective - 200 - Easy
> Watson: The criminal's wiped down the crime scene! How can we find them now? Holmes: Elementary, my dear Watson
> 
> [https://storage.ebucket.dev/out.bmp](https://storage.ebucket.dev/out.bmp)

Slightly off-white pixels. Just replace `0, 0, 0` with `255, 255, 255` and see:

![](https://i.imgur.com/zokAoUZ.png)

flag:`bucket{r3plAc3_c0L0Rs!!}`

[Back to TOC](#toc)

### Transmission - 278 - Easy
> The United States space force was one day containing routine tests on intergalactic light when they captured a random beam of light. Senior General Hexy Pictora believes this beam of light may actually be a new communication method used by aliens. Analyze the image to find out of any secrets are present.
> 
> [https://storage.ebucket.dev/beamoflight.png](https://storage.ebucket.dev/beamoflight.png)

Pixels of the image are actually just bytes of plaintext, 
```python
from PIL import Image

img = Image.open("beamoflight.png")
pixels = img.load()

msg = b''
for y in range(img.size[1]):
    for x in range(img.size[0]):
        msg += bytes(pixels[x, y])

print(msg.decode())
```
```
02:03:47: Alien Species 1: Greetings, unidentified spacecraft. This is the Andromedan Confederation. State your intentions.

02:03:50: Alien Species 2: Hello, Andromedan Confederation. This is the Sagittarian Alliance. We come in peace and wish to establish communication with your species.

02:03:53: Andromedan Confederation: We acknowledge your message, Sagittarian Alliance. We too come in peace. What is it that you wish to communicate about?

02:03:56: Sagittarian Alliance: We are interested in establishing a mutual defense agreement with your confederation. We have encountered hostile forces in this sector and believe that we can work together to protect our civilizations.

02:04:00: Andromedan Confederation: Your proposal is intriguing, Sagittarian Alliance. We will need to discuss this with our council and get back to you. In the meantime, can you tell us more about the hostile forces you have encountered?

02:04:04: Sagittarian Alliance: We have reason to believe that they are part of a larger coalition that seeks to dominate this sector of the galaxy. They are highly advanced and have already destroyed several of our outposts.

02:04:09: Andromedan Confederation: We are sorry to hear that. We too have had encounters with hostile forces in this sector. We will do everything in our power to assist you.

02:04:13: Sagittarian Alliance: Thank you, Andromedan Confederation. We have a message that we would like to send to you privately. Is there a secure channel that we can use?

02:04:18: Andromedan Confederation: Yes, we have a secure channel that we can open. We will send you the coordinates now.

02:04:22: Sagittarian Alliance: Thank you, Andromedan Confederation. We are sending the message now.

#####
bucket{d3c0d3_th3_png_f7c74c1dc7}
#####

02:04:25: Andromedan Confederation: Message received. We will keep this information confidential and use it to aid in our joint defense efforts.

02:04:29: Sagittarian Alliance: We trust that you will. Thank you for your cooperation, Andromedan Confederation. We look forward to working with you.

02:04:33: Andromedan Confederation: Likewise, Sagittarian Alliance. Until next time, safe travels.
```
flag: `bucket{d3c0d3_th3_png_f7c74c1dc7}`

[Back to TOC](#toc)

### clocks - 366 - Medium
> One of my cybersecurity professors, Dr. Timely, randomly sent my this file and said if I can decode the message he will give me an A in the class. Can you help me out?
>
> [https://storage.ebucket.dev/clocks_medium.pcap](https://storage.ebucket.dev/clocks_medium.pcap)

The flavortext obviously points to the time that the packets were sent, so let's first look at that.

![](https://i.imgur.com/o5J1mRc.png)

We can see that the difference is either close to 0.1 seconds or close to 0.5 seconds, so we just assume that those are bits and decode from there.

```python
from pyshark import FileCapture

cap = FileCapture('clocks_medium.pcap')

last_time = float(cap[0].sniff_timestamp)
bits = []
for packet in cap:
    diff = float(packet.sniff_timestamp) - last_time
    if diff < 0.01:
        continue

    if diff < 0.25:
        bits.append(0)
    else:
        bits.append(1)
    last_time = float(packet.sniff_timestamp)

print(''.join(map(str, bits)))

from Crypto.Util.number import long_to_bytes
print(long_to_bytes(int(''.join(map(str, bits)), 2)))
```
flag: `bucket{look_at_the_times_sometimes}`

[Back to TOC](#toc)

### Minecraft 2 - 398 - Easy
> I put the secret on a sign under some blocks you can't break. Good try finding what it says. IP: 5.78.67.233:5000 Note: The server is in offline mode so no account is needed VERSION 1.8.9

My second first blood.
I don't have a screenshot but this one is just using an X-ray texture pack:joy_cat:. Pretty funny challenge tbh, not that hard if you've ever played Minecraft before though.

### Clocks 2 - 408 - Hard
> One of my cybersecurity professors, Dr. Timely, randomly sent my this file and said if I can decode the message he will give me an A in the class. Can you help me out?
> 
> [https://storage.ebucket.dev/clocks_hard.pcap](https://storage.ebucket.dev/clocks_hard.pcap)

Revenge of the last clocks challenge, this time the times are much less distinct.

![](https://i.imgur.com/k3JgVuI.png)

Still, we can easily notice a small time gap and a large time gap between some packets. Through some luck ~~and guessing~~, we find that 0.5 works as a divider.

```python
from pyshark import FileCapture

cap = FileCapture('clocks_hard.pcap')

last_time = float(cap[0].sniff_timestamp)
bits = []
for packet in cap:
    diff = float(packet.sniff_timestamp) - last_time
    if diff < 0.01:
        continue

    if diff < 0.5:
        bits.append(0)
    else:
        bits.append(1)
    last_time = float(packet.sniff_timestamp)

print(''.join(map(str, bits)))

from Crypto.Util.number import long_to_bytes
print(long_to_bytes(int(''.join(map(str, bits)), 2)))
```
flag: `bucket{clocks_are_crazy_sometimes}`

[Back to TOC](#toc)

### Drawing - 456 - Easy
> I caught a criminal drawing one of my art pieces. Im not sure what it is but the police don't want me to just wipe it out. Could you help out?
> 
> [https://storage.ebucket.dev/bucket.webp](https://storage.ebucket.dev/bucket.webp)
> [https://storage.ebucket.dev/transform.webp](https://storage.ebucket.dev/transform.webp)

I'm not sure what the deal with the low solve count on this was, it's literally the same as transmission but only the alpha channel. You can tell pretty clearly just looking at the pixels on `transform.webp`

```python
from PIL import Image

img = Image.open("transform.webp")

for i in range(1):
    for j in range(img.size[1]):
        pixel = img.getpixel((i, j))
        print(chr(pixel[3]), end='')
```
flag: `bucket{1_l0v3_w3bp_f77c069c7}`

[Back to TOC](#toc)

### Secret Bucket - 492 - Medium
> I think I lost my flag somewhere in my bucket! Good thing I always have it around for emergencies.
> Colors have nothing to do with it.
> 
> [https://storage.ebucket.dev/outBucket.bmp](https://storage.ebucket.dev/outBucket.bmp)

This one *looks* like another steg at first, except you use the 4th bit. However, decoding gives garbage...

![](https://i.imgur.com/TivWUd2.png)

Looking into the hex of the file however, we can spot the issue.

![](https://i.imgur.com/vt6rrkq.png)

The large chunk of 0's and 1's (the flag bits), starts at 0x30. However, in the BMP file header, which is outlined in red, has the start of the image begin at 0x36 (the underlined red part). This means the pixel data starts at 0x36, which is what the steg was using to decode.

To extract the flag ourselves, we just do it manually with the bytes of the file.
```python
data = open("outBucket.bmp","rb").read()
data = data[0x30:]

mask = 16
bits = ""   
for b in data[:1000]:
    if b & mask:
        bits += "1"
    else:
        bits += "0"

from Crypto.Util.number import long_to_bytes
msg = long_to_bytes(int(bits, 2))

print(msg)
# b'}??s1SYlaNa_L3NnaHc_3Ldd1m{tekcub}??s1SYlaNa_L3NnaHc_3Ldd1m{tekcub}??s1SYlaNa_L3NnaHc_3Ldd1m{tekcub}??s1SYlaNa_L3NnaHc_3Ldd1m'
print(msg[::-1].decode())
```
flag: `bucket{m1ddL3_cHanN3L_aNalYS1s??}`

[Back to TOC](#toc)

## Crypto
Math math mathy math.
Not much to say here besides how stupid I am for not solving search-3 in time lmao. Pretty easy challenge, always miss the easiest things.

### Search-0 - 380 - Easy
> Johnny's a math whiz and figured out a method to encrypt his messages securely. He's a bad programmer though, and his program seems to be leaking some important bits. Can you decrypt the flag?
> 
> [https://storage.ebucket.dev/search_0_generator.py](https://storage.ebucket.dev/search_0_generator.py)

Source: 
```python
from Crypto.Util.number import getPrime, inverse, bytes_to_long
from string import ascii_letters, digits
from random import choice

m = open("flag.txt", "rb").read()
p = getPrime(128)
q = getPrime(128)
n = p * q
e = 65537
l = (p-1)*(q-1)
d = inverse(e, l)

m = pow(bytes_to_long(m), e, n)
print(m)
print(n)

p = "{0:b}".format(p)
for i in range(0,108):
    print(p[i], end="")
```
Well Johnny is a bit blind to be missing that he's leaking almost his entire prime, so we just brute force the rest of it for him.
```python
from pwn import remote
# 213.133.103.186:6612
r = remote('213.133.103.186', 5001)

c = int(r.recvline().split()[-1])
n = int(r.recvline().split()[-1])
print(c, n)
leak = r.recvall().split()[-1]
print(leak)
leak = int(leak, 2)

test_p = leak << 20
p = 0
for bottom in range(1 << 20):
    p = test_p + bottom
    if n % p == 0:
        break

q = n // p
assert p * q == n

e = 0x10001
l = (p-1)*(q-1)
d = pow(e, -1, l)

m = pow(c, d, n)
from Crypto.Util.number import long_to_bytes
print(long_to_bytes(m).decode())
```
flag: `bucket{m3m0ry_L3Aks_4R3_bAD}`

[Back to TOC](#toc)

### Search-1 - 390 - Medium
> Johnny patched the previous leak, but seems to have created a new one. See if you can still decrypt the flag.
> 
> [https://storage.ebucket.dev/search_1_generator.py](https://storage.ebucket.dev/search_1_generator.py)

Source
```python
from Crypto.Util.number import getPrime, inverse, bytes_to_long
from string import ascii_letters, digits
from random import choice

m = open("flag.txt", "rb").read()
p = getPrime(128)
q = getPrime(128)
n = p * q
e = 65537
l = (p-1)*(q-1)
d = inverse(e, l)

m = pow(bytes_to_long(m), e, n)
print(m)
print(n)
leak = (p-2)*(q-2)
print(leak)
```

Leaking $(p-2) (q-2)$ actually leaks $p + q$ through simple algebra:

$$ 
\begin{aligned}
(p-2)(q-2) &= pq - 2p - 2q + 4 \\\\
n &= pq \\\\
n - (p-2)(q-2) &= 2p + 2q - 4& \\\\
\frac{n - ((p-2)(q-2) - 4)}{2} &= p + q
\end{aligned}
$$

And given $p+q$, we can easily solve for $p$ and $q$ individually through the quadratic formula:
$$ 
\begin{aligned}
s &= p + q \\\\
n &= pq \\\\
\\\\
&\text{Create quadratic with primes as roots} \\\\
f(x) &= (x - p)(x - q) \\\\
f(x) &= x^2 - (p + q)x + pq \\\\
f(x) &= x^2 - sx + n \\\\
p,q &= \frac{s \pm \sqrt{s^2 - 4n}}{2}
\end{aligned}
$$

```python
from pwn import remote
# 213.133.103.186:6989
r = remote('213.133.103.186', 6989)

c = int(r.recvline().split()[-1])
n = int(r.recvline().split()[-1])
leak = int(r.recvline().split()[-1])

s = n - (leak - 4)
s //= 2

from gmpy2 import isqrt

discrim = s**2 - 4*n
assert isqrt(discrim)
test = int(isqrt(discrim))

test_p = (s + test) // 2
if n % test_p != 0:
    test_p = (s - test) // 2

p = test_p
q = n // p
assert p * q == n

e = 0x10001
l = (p-1)*(q-1)
d = pow(e, -1, l)

m = pow(c, d, n)
from Crypto.Util.number import long_to_bytes
print(long_to_bytes(m))
```
flag: `bucket{d0nt_l34K_pr1v4T3_nUmS}`

[Back to TOC](#toc)

### Search-2 - 422 - Medium
> Johnny really thinks he's got it this time. Literally a hundred percent sure. Maybe. Possibly. Perchance.
> 
> [https://storage.ebucket.dev/search_2_generator.py](https://storage.ebucket.dev/search_2_generator.py)

```python
from Crypto.Util.number import getPrime, inverse, bytes_to_long, isPrime
from string import ascii_letters, digits
from random import choice

p = bytes_to_long(open("flag.txt", "rb").read())
m = 0
while not isPrime(p):
    p += 1
    m += 1
q = getPrime(len(bin(p)))
n = p * q
e = 65537
l = (p-1)*(q-1)
d = inverse(e, l)

m = pow(m, e, n)
print(m)
print(n)
print(d)
```
We're given `d`, so we can just follow this algorithm to factor `n`:
https://crypto.stackexchange.com/questions/6361/is-sharing-the-modulus-for-multiple-rsa-key-pairs-secure

```python
from pwn import remote
# 213.133.103.186:7420
r = remote('213.133.103.186', 7420)
import random
import math

c = int(r.recvline().split()[-1])
n = int(r.recvline().split()[-1])
d = int(r.recvline().split()[-1])

e = 0x10001

def remove_even(n):
    if n == 0:
        return (0, 0)
    r = n
    t = 0
    while (r & 1) == 0:
        t = t + 1
        r = r >> 1
    return (r, t)
def get_root_one(x, k, N):
    (r, t) = remove_even(k)
    oldi = None
    i = pow(x, r, N)
    while i != 1:
        oldi = i
        i = (i*i) % N
    if oldi == N-1:
        return None 
    return oldi
def factor_rsa(e, d, N):
    k = e*d - 1
    y = None
    while not y:
        x = random.randrange(2, N)
        y = get_root_one(x, k, N)
    p = math.gcd(y-1, N)
    q = N // p
    return (p, q)

p, q = factor_rsa(e, d, n)
print(p, q)
assert p * q == n

from Crypto.Util.number import long_to_bytes
m = pow(c, d, n)
flag = p - m
print(long_to_bytes(flag))
```
flag: `bucket{sw1tCH1nG_D1dNT_W0rK}`

[Back to TOC](#toc)

### Search-3 - 470 - Hard
> Nah nah, now it's official. Johnny has to have figured it out by now
> 
> [https://storage.ebucket.dev/search_3_generator.py](https://storage.ebucket.dev/search_3_generator.py)

Just CRT across different queries to recover the full flag, since decryption only gives us a value with the same `mod p`.

Also something to note, $\phi = p(p-1)$ instead of $(p-1)(q-1)$ because $n = p^2$

```python
from pwn import remote
# # 213.133.103.186:7194
from gmpy2 import isqrt
e = 0x10001

Ms = []
Ps = []

for i in range(3):
    r = remote('213.133.103.186', 7194, level='error')
    m = int(r.recvline().strip())
    n = int(r.recvline().strip())
    r.close()
    p = int(isqrt(n))
    phi = p * (p - 1)
    d = pow(e, -1, phi)

    Ms.append(pow(m, d, n))
    Ps.append(p)

from sympy.ntheory.modular import crt
from Crypto.Util.number import long_to_bytes
m = crt(Ps, Ms)[0]
print(long_to_bytes(m))
```
flag: `bucket{th4_F1N4l_L3v3l_0f_3nCRypT10N}`

[Back to TOC](#toc)

### Rotund Bits - 474 - Easy
> Synonyms are your friend here.
> 
> Look at the meaning(s) of rotund (the bits aren't fat)
> 
> Hint for rotund bits: I intended rotund's synonym to be round, but that is apparently not an exact synonym. If you couldn't tell, my grasp on all languages, python or English, is kinda bad :p.
> 
> [https://storage.ebucket.dev/out](https://storage.ebucket.dev/out)

I'm just gonna let the script speak for itself.
```python
data = open("file.out").read()
data = data.split(" ")
data = [x.split("0x")[1:] for x in data][:-1]
for d in data:
    print(d)

data = [[int(x, 16) for x in line] for line in data]
data = [[bin(x)[2:].zfill(8) for x in line] for line in data]
for d in data:
    print(d)

msg = ""
for d in data:
    b = ""
    for x in d:
        b += x[0]
    msg += chr(int(b, 2))
print(msg)
```
Yes, it's literally just the top bits of each hex in each group...
flag: `bucket{bINaRy_r0uND1nG_15_w31Rd.!.}`

[Back to TOC](#toc)

### SCAlloped_potatoes - 484 - Medium
> I'm using a potato battery farm to power my computer. I know potatoes are virtually indestructible, but is my RSA decryption key still safe from a physical attack? hint: For the SCAlloped potatoes challenge, look at what operations are used while decrypting RSA and figure out how they are implemented in computers."
> 
> [https://storage.ebucket.dev/powerTrace.txt](https://storage.ebucket.dev/powerTrace.txt)

Looking at the graph of the power trace reveals a pattern:

![](https://i.imgur.com/6UH3tvq.png)

If we assume that these are flag bits (which isn't normal power analysis, but something that was hinted to me after I complained in a ticket :p), then we can deduce this pattern here: 

![](https://i.imgur.com/zgDBMLe.png)

(Correction: The first 0 of every byte should be represented by the low voltage groups)

This matches the first few bytes of `bucket{`, as `b` is `01100010`, `u` is `01110101`, and `c` is `01100011`.

Numerically, this means every `1` is a group of medium voltage bits followed by a group of high voltage bits, while a `0` is just a group of medium voltage bits.

Looking at the data, we can see that the first `1` seems to appear after a group of 10 low voltage numbers as a group of 10 medium voltage numbers and 10 high voltage numbers, so we can assume each group is around 10 numbers.

```python
power = eval(open("data.txt").read())
print(power, len(power))

from matplotlib import pyplot as plt
plt.plot(power)
plt.show()

byt = []
msg = ""
for i in range(len(power)):
    if power[i] < 125: # low voltage seperator
        if byt:
            chunks = [] # condense groups of 10
            for j in range(0, len(byt), 10):
                chunks.append(sum(byt[j:j+10]) / 10)
            
            # walk chunks
            j = 0
            byt = "0"
            while j < len(chunks):
                if j < len(chunks) - 1 and chunks[j] < 175 and chunks[j + 1] > 175:
                    byt += "1"
                    j += 2
                else:
                    byt += "0"
                    j += 1
            msg += chr(int(byt, 2))
            byt = []
    else:
        byt.append(power[i]) 
print(msg)
```
flag: `bucket{I5_tH15_aN_NSA_baCkDoOr?}`

[Back to TOC](#toc)

## Rev
Saving most of these for another post :stuck_out_tongue_winking_eye:... 
See you there.

### Troll - 464 - Hard
> How well do you know your destiny 2 lore? Luke smith will test you.
> 
> [https://storage.ebucket.dev/out.jar](https://storage.ebucket.dev/out.jar)

We start out with a `jar`, so let's decompile it first and see what's actually going on. 

I'm using [http://www.javadecompilers.com/](http://www.javadecompilers.com/) to decompile the `jar` as I'm too lazy to download `jadx` and the site at least gives multiple options to cross compare.

But the output of the decompilation is still obfuscated :unamused:.
Here's the `jadx` output changed as little as possible to fix all compilation errors:
```java
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Main {

    private static String[] f0I = null;
    private static int[] f1l = null;
    public static ArrayList<String> questions;

    static {
        lII();
        m3ll();
        String[] strArr = new String[f1l[7]];
        strArr[f1l[0]] = f0I[f1l[8]];
        strArr[f1l[1]] = f0I[f1l[9]];
        strArr[f1l[2]] = f0I[f1l[10]];
        strArr[f1l[3]] = f0I[f1l[11]];
        strArr[f1l[4]] = f0I[f1l[12]];
        strArr[f1l[5]] = f0I[f1l[13]];
        strArr[f1l[6]] = f0I[f1l[14]];
        strArr[f1l[8]] = f0I[f1l[15]];
        strArr[f1l[9]] = f0I[f1l[16]];
        strArr[f1l[10]] = f0I[f1l[17]];
        strArr[f1l[11]] = f0I[f1l[18]];
        strArr[f1l[12]] = f0I[f1l[19]];
        strArr[f1l[13]] = f0I[f1l[20]];
        strArr[f1l[14]] = f0I[f1l[21]];
        strArr[f1l[15]] = f0I[f1l[22]];
        strArr[f1l[16]] = f0I[f1l[23]];
        strArr[f1l[17]] = f0I[f1l[24]];
        strArr[f1l[18]] = f0I[f1l[25]];
        strArr[f1l[19]] = f0I[f1l[26]];
        strArr[f1l[20]] = f0I[f1l[27]];
        strArr[f1l[21]] = f0I[f1l[7]];
        strArr[f1l[22]] = f0I[f1l[28]];
        strArr[f1l[23]] = f0I[f1l[29]];
        strArr[f1l[24]] = f0I[f1l[30]];
        strArr[f1l[25]] = f0I[f1l[31]];
        strArr[f1l[26]] = f0I[f1l[32]];
        strArr[f1l[27]] = f0I[f1l[33]];
        questions = new ArrayList<>(Arrays.asList(strArr));
    }

    public static String FLAG = System.getenv(f0I[f1l[5]]);
    public static String answer = f0I[f1l[6]];
    
    private static String m0I(String llllllllllIlIlI, String llllllllllIlIIl) {
        try {
            SecretKeySpec llllllllllIllIl = new SecretKeySpec(Arrays.copyOf(MessageDigest.getInstance("MD5").digest(llllllllllIlIIl.getBytes(StandardCharsets.UTF_8)), f1l[9]), "DES");
            Cipher instance = Cipher.getInstance("DES");
            instance.init(f1l[2], llllllllllIllIl);
            return new String(instance.doFinal(Base64.getDecoder().decode(llllllllllIlIlI.getBytes(StandardCharsets.UTF_8))), StandardCharsets.UTF_8);
        } catch (Exception llllllllllIlIll) {
            llllllllllIlIll.printStackTrace();
            return null;
        }
    }

    /* renamed from: l */
    private static String m1l(String lllllllllIIlIII, String lllllllllIIllII) {
        String str = new String(Base64.getDecoder().decode(lllllllllIIlIII.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
        StringBuilder lllllllllIIlIll = new StringBuilder();
        char[] lllllllllIIlIlI = lllllllllIIllII.toCharArray();
        int lllllllllIIlIIl = f1l[0];
        char[] charArray = str.toCharArray();
        int length = charArray.length;
        int i = f1l[0];
        while (lIII(i, length)) {
            lllllllllIIlIll.append((char) (lllllllllIIlIlI[lllllllllIIlIIl % lllllllllIIlIlI.length] ^ charArray[i]));
            "".length();
            lllllllllIIlIIl++;
            i++;
            "".length();
        }
        return String.valueOf(lllllllllIIlIll);
    }

    /* renamed from: lI */
    private static String m2lI(String lllllllllIlllIl, String lllllllllIllIlI) {
        try {
            SecretKeySpec llllllllllIIIII = new SecretKeySpec(MessageDigest.getInstance("MD5").digest(lllllllllIllIlI.getBytes(StandardCharsets.UTF_8)), "Blowfish");
            Cipher lllllllllIlllll = Cipher.getInstance("Blowfish");
            lllllllllIlllll.init(f1l[2], llllllllllIIIII);
            return new String(lllllllllIlllll.doFinal(Base64.getDecoder().decode(lllllllllIlllIl.getBytes(StandardCharsets.UTF_8))), StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static void lII() {
        f1l = new int[35];
        f1l[0] = ((-" ".length()) ^ 49) & 49;
        f1l[1] = " ".length();
        f1l[2] = "  ".length();
        f1l[3] = "   ".length();
        f1l[4] = 4;
        f1l[5] = 5;
        f1l[6] = 6;
        f1l[7] = 27;
        f1l[8] = 7;
        f1l[9] = 8;
        f1l[10] = 9;
        f1l[11] = 10;
        f1l[12] = 11;
        f1l[13] = 12;
        f1l[14] = 13;
        f1l[15] = 14;
        f1l[16] = 15;
        f1l[17] = 16;
        f1l[18] = 17;
        f1l[19] = 18;
        f1l[20] = 19;
        f1l[21] = 20;
        f1l[22] = 21;
        f1l[23] = 22;
        f1l[24] = 23;
        f1l[25] = 24;
        f1l[26] = 25;
        f1l[27] = 26;
        f1l[28] = 28;
        f1l[29] = 29;
        f1l[30] = 30;
        f1l[31] = 31;
        f1l[32] = 32;
        f1l[33] = 33;
        f1l[34] = 34;
    }

    private static boolean lIII(int i, int i2) {
        return i < i2;
    }

    private static boolean lIl(int i, int i2) {
        return i != i2;
    }

    /* renamed from: ll */
    private static void m3ll() {
        f0I = new String[f1l[34]];
        f0I[f1l[0]] = m0I("M/b6LLu69fV+83nC8P7cm3NFbwzMtVJqvcj4KgrkM1oP6WezWoyCF0V4emNjq8Lr", "RGFHA");
        f0I[f1l[1]] = m1l("K2kHIgEOaRE4BkIwHz5NA2kDLh8LLANrAgRpAT4IET0ZJAMRZVAqAwZpET9NFiEVawgMLVAiC0IwHz5NAycDPAgQaQQjCA9pMQchQiofOR8HKgQnFE5pCSQYQiQZLAUWaRcuGUIvHCoKTA==", "bIpKm");
        f0I[f1l[2]] = m2lI("dd6iCFEwZ2klnD1az2dXLSR/NK9T/iR3X0il3BwwlhUk9L5OG6hymVElvLh4wIS8Dn/DOqWtgef2jSmMWRtjMw==", "djaDa");
        f0I[f1l[3]] = m0I("E5g1tM7xB/I=", "LZHyW");
        f0I[f1l[4]] = m2lI("4AdI/0mTyFRnfr75NpLgag==", "RpPkm");
        f0I[f1l[5]] = m2lI("L0t7r/fDEXI=", "OGtWu");
        f0I[f1l[6]] = m1l("ZiNmXH1jIzNcKjJ2MQkqZHNj", "PBRoI");
        f0I[f1l[8]] = m2lI("YYacupVSSuGFdB7+vShn5fbMz8Bu8XagjZZEXDsbAtODn/xfwfzIDA==", "qUEDX");
        f0I[f1l[9]] = m1l("OSw0GkoHN3UaAgtkMxsGAmQ7DwcLZDoIShosME4MByo0AkoMKyYdSgcqdRoCC2Q5DxkaZCIHGQZ7", "nDUnj");
        f0I[f1l[10]] = m0I("4uK7g3MKtHnoNDeRWLb6yPq0yoKwxIQgaQdWnXmUXey5u3eWZk7B6qGCzd55gtMC", "vOgjG");
        f0I[f1l[11]] = m0I("eOVkXQG4iWlaMF9FrJ2BHY4La192LJOfl5k9i+LuNJ+Lv3/CzEXt7qVOQuoKXX9o", "PUPyS");
        f0I[f1l[12]] = m0I("UHXIyKrSgcVHARWFDRZ78RFyxDhz8uNAvzJizKPOHx5fG5uBbBCB3A==", "YWDUY");
        f0I[f1l[13]] = m0I("F+5EeR6FRrQiFFbVB1ANdxhJrUxRPVyhkqwgws0XAmXu/pvVbQaL9qffvgK+u0kOFQBzqlPPAvuUGdTDiY2PcBqc6xJ4eElc/HgnYNXn436EAs1MB8o5UIJo0SMBexqsFQBzqlPPAvvH9N1RmFJ8BQ==", "RsvRt");
        f0I[f1l[14]] = m0I("DVw06+nt0YxuTCDJRfDhD5K1m5FvyrpFkmUfnNiGx6j2yE/y96DUB7MUFbjn3T4Xlt1F2OC5EIw=", "sDwKZ");
        f0I[f1l[15]] = m1l("DykMOhh4Igo1HyphEjgDeDUNPFA8JAQ9UDczBzAEeCcEOgQxLgt5HTcyEXkTNC4WPBwhYQQqAzciDDgEPSVFLhksKVo=", "XAeYp");
        f0I[f1l[16]] = m1l("Hgc1bxk3BjtvAD8FJzxUPgkxbxY3BjEnETNEYjscM0glOholBSs7HHpIICoROEgwKgczHH0=", "VhBOt");
        f0I[f1l[17]] = m1l("OT0VOW0HJlQ5JQt1EjghAnUaLCALdQIoPx08GyNtATNUOSULdTEJF1E=", "nUtMM");
        f0I[f1l[18]] = m2lI("edwQLeONPQclNxWUb27/t8rFB+gWfNjEvUAa4Zfo0/R0j1U3KhImmzrjUCLuqWDg6EH0G4SW+dU=", "tgLJs");
        f0I[f1l[19]] = m1l("IAA0CwlXDDgdTAQJOBcYWlllWR8SCSMaBFcfORwCVwQ+FgceBjZZChgacRYfHho4ClM=", "whQyl");
        f0I[f1l[20]] = m1l("IQ0qDEEfFmsMCRNFJRkME0UkHkEVBDIcBFtTbAtBEQ0kCxVJ", "veKxa");
        f0I[f1l[21]] = m2lI("FitSGCVFAwM86UBfr9D19x/2NibvF6DKrMd2QXID6TLRX4seI/DQ063o3jGtj6fBA0HqLOs6Z02Gux1pHKcgZg==", "wbUkv");
        f0I[f1l[22]] = m1l("LSM5CzFaLigHLRMocB88Gzs/BnkILiMNNBgnNRt5G2s8DS8fOX0JOg4iPwZ5CCI2BDxF", "zKPhY");
        f0I[f1l[23]] = m0I("z13Xv5GHGP7WC2+WYv39T+3urhKILaG+Nx6NexC96OLHJV7ZcNuC3JIKvji4g3rx", "gmqqx");
        f0I[f1l[24]] = m2lI("IfOB2u6Mun+oaAudIYaOUqNpZOYlQE9v", "etzcE");
        f0I[f1l[25]] = m2lI("pAgOYtfo/KfX9j2ucqpSc6smDo/1GbnA4z8aO3hP2aD2IxwrunTx0y9XeOnASaikOvDrLPUYYXVB5sU1YOJzmkpVLQ7R94WdMHBb+vXbsv5Nk0eyvRlXsg==", "MTvaD");
        f0I[f1l[26]] = m2lI("/TVvXx3IErUYFDzua4OA18G2gSg52QLow3CPr69+xJbMkXTyBS1keCG1VPzQJSXYgJHIE9+A1b9YnDTU6wYtMw==", "QYLHR");
        f0I[f1l[27]] = m0I("MM2+sqt8W/kCJVZZ4arp35LrAX1IRPkQOYa4e6/jMAQ1tTJuL86X2I9UOjKwoiabznuHJbY3ogg=", "UlQSk");
        f0I[f1l[7]] = m2lI("Cf6N5mya/5KkhookR5KQsegRGLg4gT5f/R80Zha54Hjs4O+7yMZ08O45ukn6T2pxEvxM4ry3s3TXn4bmlXUcHQ==", "elVkr");
        f0I[f1l[28]] = m1l("Jxg8RTkQHzdFPxVQLQ01UxUhETUdFDwBcBERKxc1H1ApACIYUDAWcAcYPEUjEh08RTEAUC4NORAYeRY4HAQ+ED5TADwXO0w=", "spYeP");
        f0I[f1l[29]] = m1l("Ly82JWwPJiRxOBAidz8tFSJ3PipYMz80bBYoJTUlG2cxMC8MLjg/bBchdyUkHWc1PS0bLHcwPhUoJShz", "xGWQL");
        f0I[f1l[30]] = m2lI("g4GLak/p+Mnozn2aqbtcrwOvncQ8dV9ioM7LVe2OuLsgIVdBdolr7WR7+Ab9J0qMfcKu6w4wLJhL7mo3xww1WnDDpqAlRfJPRpj/L7C2geJThwNKc4FnGE1chHctsZRD", "eVXCB");
        f0I[f1l[31]] = m1l("AD4dCwN3OxsMSzA/Ag0YdzdUDgIvMxBIGzgkAAEEOXYbDks/MxUEHz92ARgEOXYXBwc7MxccAjkxVAkFdzkGCks4MFQYBCAzBlc=", "WVthk");
        f0I[f1l[32]] = m1l("IwYQFDFUGRwWKRsAWQQtFRpZHjcXHBwWKhEdWQMxEU4dBTgDThgZPVQdDRguVB0JEjwQThYReRVODhI4BAEXSA==", "tnywY");
        f0I[f1l[33]] = m1l("IwsVciEKChtyJwULFTxsCgwDPycKFgNyPx8NDj5sBw0UN3M=", "kdbRL");
    }

    private static boolean llI(int i) {
        return i == 0;
    }

    private static boolean lll(int i) {
        return i != 0;
    }

    public static void main(String[] strArr) {
        System.out.println(f0I[f1l[0]]);
        System.out.println(f0I[f1l[1]]);
        System.out.println(f0I[f1l[2]]);
        StringBuilder sb = new StringBuilder();
        Scanner scanner = new Scanner(System.in);
        while (lIl(sb.length(), answer.length())) {
            int nextInt = new Random().nextInt(questions.size());
            String lllllllllllIIll = questions.get(nextInt);
            System.out.println(lllllllllllIIll);
            String nextLine = scanner.nextLine();
            if (llI(nextLine.equals(f0I[f1l[3]]) ? 1 : 0)) {
                sb.append(lllllllllllIIll.charAt(nextInt - Integer.parseInt(nextLine)));
                "".length();
            }
            "".length();
            if (0 != 0) {
                return;
            }
        }
        if (lll(String.valueOf(sb).equals(answer) ? 1 : 0)) {
            System.out.println(FLAG);
            "".length();
            if ("   ".length() >= 4) {
            }
            return;
        }
        System.out.println(f0I[f1l[4]]);
    }
}
```

Let's clean some of this up...

First we can start with the smallest functions and useless statements.
For example, a line with just `"".length()` does absolutely nothing, so we can just remove it. 
The same can be said for trivial functions like:
```java
private static boolean llI(int i) {
    return i == 0;
}

private static boolean lll(int i) {
    return i != 0;
}
```

Here's what the script looks like with those removed.

```java
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Main {

    private static String[] f0I = null;
    private static int[] f1l = null;
    public static ArrayList<String> questions;

    static {
        lII();
        m3ll();
        String[] strArr = new String[f1l[7]];
        strArr[f1l[0]] = f0I[f1l[8]];
        strArr[f1l[1]] = f0I[f1l[9]];
        strArr[f1l[2]] = f0I[f1l[10]];
        strArr[f1l[3]] = f0I[f1l[11]];
        strArr[f1l[4]] = f0I[f1l[12]];
        strArr[f1l[5]] = f0I[f1l[13]];
        strArr[f1l[6]] = f0I[f1l[14]];
        strArr[f1l[8]] = f0I[f1l[15]];
        strArr[f1l[9]] = f0I[f1l[16]];
        strArr[f1l[10]] = f0I[f1l[17]];
        strArr[f1l[11]] = f0I[f1l[18]];
        strArr[f1l[12]] = f0I[f1l[19]];
        strArr[f1l[13]] = f0I[f1l[20]];
        strArr[f1l[14]] = f0I[f1l[21]];
        strArr[f1l[15]] = f0I[f1l[22]];
        strArr[f1l[16]] = f0I[f1l[23]];
        strArr[f1l[17]] = f0I[f1l[24]];
        strArr[f1l[18]] = f0I[f1l[25]];
        strArr[f1l[19]] = f0I[f1l[26]];
        strArr[f1l[20]] = f0I[f1l[27]];
        strArr[f1l[21]] = f0I[f1l[7]];
        strArr[f1l[22]] = f0I[f1l[28]];
        strArr[f1l[23]] = f0I[f1l[29]];
        strArr[f1l[24]] = f0I[f1l[30]];
        strArr[f1l[25]] = f0I[f1l[31]];
        strArr[f1l[26]] = f0I[f1l[32]];
        strArr[f1l[27]] = f0I[f1l[33]];
        questions = new ArrayList<>(Arrays.asList(strArr));
    }

    public static String FLAG = System.getenv(f0I[f1l[5]]);
    public static String answer = f0I[f1l[6]];

    private static String m0I(String llllllllllIlIlI, String llllllllllIlIIl) {
        try {
            SecretKeySpec llllllllllIllIl = new SecretKeySpec(Arrays.copyOf(
                    MessageDigest.getInstance("MD5").digest(llllllllllIlIIl.getBytes(StandardCharsets.UTF_8)), f1l[9]),
                    "DES");
            Cipher instance = Cipher.getInstance("DES");
            instance.init(f1l[2], llllllllllIllIl);
            return new String(
                    instance.doFinal(Base64.getDecoder().decode(llllllllllIlIlI.getBytes(StandardCharsets.UTF_8))),
                    StandardCharsets.UTF_8);
        } catch (Exception llllllllllIlIll) {
            llllllllllIlIll.printStackTrace();
            return null;
        }
    }

    private static String m1l(String lllllllllIIlIII, String lllllllllIIllII) {
        String str = new String(Base64.getDecoder().decode(lllllllllIIlIII.getBytes(StandardCharsets.UTF_8)),
                StandardCharsets.UTF_8);
        StringBuilder lllllllllIIlIll = new StringBuilder();
        char[] lllllllllIIlIlI = lllllllllIIllII.toCharArray();
        int lllllllllIIlIIl = f1l[0];
        char[] charArray = str.toCharArray();
        int length = charArray.length;
        int i = f1l[0];
        while (i < length) {
            lllllllllIIlIll.append((char) (lllllllllIIlIlI[lllllllllIIlIIl % lllllllllIIlIlI.length] ^ charArray[i]));
            lllllllllIIlIIl++;
            i++;
        }
        return String.valueOf(lllllllllIIlIll);
    }

    private static String m2lI(String lllllllllIlllIl, String lllllllllIllIlI) {
        try {
            SecretKeySpec llllllllllIIIII = new SecretKeySpec(
                    MessageDigest.getInstance("MD5").digest(lllllllllIllIlI.getBytes(StandardCharsets.UTF_8)),
                    "Blowfish");
            Cipher lllllllllIlllll = Cipher.getInstance("Blowfish");
            lllllllllIlllll.init(f1l[2], llllllllllIIIII);
            return new String(
                    lllllllllIlllll
                            .doFinal(Base64.getDecoder().decode(lllllllllIlllIl.getBytes(StandardCharsets.UTF_8))),
                    StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static void lII() {
        f1l = new int[35];
        f1l[0] = 0;
        f1l[1] = 1;
        f1l[2] = 2;
        f1l[3] = 3;
        f1l[4] = 4;
        f1l[5] = 5;
        f1l[6] = 6;
        f1l[7] = 27;
        f1l[8] = 7;
        f1l[9] = 8;
        f1l[10] = 9;
        f1l[11] = 10;
        f1l[12] = 11;
        f1l[13] = 12;
        f1l[14] = 13;
        f1l[15] = 14;
        f1l[16] = 15;
        f1l[17] = 16;
        f1l[18] = 17;
        f1l[19] = 18;
        f1l[20] = 19;
        f1l[21] = 20;
        f1l[22] = 21;
        f1l[23] = 22;
        f1l[24] = 23;
        f1l[25] = 24;
        f1l[26] = 25;
        f1l[27] = 26;
        f1l[28] = 28;
        f1l[29] = 29;
        f1l[30] = 30;
        f1l[31] = 31;
        f1l[32] = 32;
        f1l[33] = 33;
        f1l[34] = 34;
    }

    private static void m3ll() {
        f0I = new String[f1l[34]];
        f0I[f1l[0]] = m0I("M/b6LLu69fV+83nC8P7cm3NFbwzMtVJqvcj4KgrkM1oP6WezWoyCF0V4emNjq8Lr", "RGFHA");
        f0I[f1l[1]] = m1l(
                "K2kHIgEOaRE4BkIwHz5NA2kDLh8LLANrAgRpAT4IET0ZJAMRZVAqAwZpET9NFiEVawgMLVAiC0IwHz5NAycDPAgQaQQjCA9pMQchQiofOR8HKgQnFE5pCSQYQiQZLAUWaRcuGUIvHCoKTA==",
                "bIpKm");
        f0I[f1l[2]] = m2lI("dd6iCFEwZ2klnD1az2dXLSR/NK9T/iR3X0il3BwwlhUk9L5OG6hymVElvLh4wIS8Dn/DOqWtgef2jSmMWRtjMw==",
                "djaDa");
        f0I[f1l[3]] = m0I("E5g1tM7xB/I=", "LZHyW");
        f0I[f1l[4]] = m2lI("4AdI/0mTyFRnfr75NpLgag==", "RpPkm");
        f0I[f1l[5]] = m2lI("L0t7r/fDEXI=", "OGtWu");
        f0I[f1l[6]] = m1l("ZiNmXH1jIzNcKjJ2MQkqZHNj", "PBRoI");
        f0I[f1l[8]] = m2lI("YYacupVSSuGFdB7+vShn5fbMz8Bu8XagjZZEXDsbAtODn/xfwfzIDA==", "qUEDX");
        f0I[f1l[9]] = m1l("OSw0GkoHN3UaAgtkMxsGAmQ7DwcLZDoIShosME4MByo0AkoMKyYdSgcqdRoCC2Q5DxkaZCIHGQZ7", "nDUnj");
        f0I[f1l[10]] = m0I("4uK7g3MKtHnoNDeRWLb6yPq0yoKwxIQgaQdWnXmUXey5u3eWZk7B6qGCzd55gtMC", "vOgjG");
        f0I[f1l[11]] = m0I("eOVkXQG4iWlaMF9FrJ2BHY4La192LJOfl5k9i+LuNJ+Lv3/CzEXt7qVOQuoKXX9o", "PUPyS");
        f0I[f1l[12]] = m0I("UHXIyKrSgcVHARWFDRZ78RFyxDhz8uNAvzJizKPOHx5fG5uBbBCB3A==", "YWDUY");
        f0I[f1l[13]] = m0I(
                "F+5EeR6FRrQiFFbVB1ANdxhJrUxRPVyhkqwgws0XAmXu/pvVbQaL9qffvgK+u0kOFQBzqlPPAvuUGdTDiY2PcBqc6xJ4eElc/HgnYNXn436EAs1MB8o5UIJo0SMBexqsFQBzqlPPAvvH9N1RmFJ8BQ==",
                "RsvRt");
        f0I[f1l[14]] = m0I("DVw06+nt0YxuTCDJRfDhD5K1m5FvyrpFkmUfnNiGx6j2yE/y96DUB7MUFbjn3T4Xlt1F2OC5EIw=", "sDwKZ");
        f0I[f1l[15]] = m1l(
                "DykMOhh4Igo1HyphEjgDeDUNPFA8JAQ9UDczBzAEeCcEOgQxLgt5HTcyEXkTNC4WPBwhYQQqAzciDDgEPSVFLhksKVo=",
                "XAeYp");
        f0I[f1l[16]] = m1l("Hgc1bxk3BjtvAD8FJzxUPgkxbxY3BjEnETNEYjscM0glOholBSs7HHpIICoROEgwKgczHH0=", "VhBOt");
        f0I[f1l[17]] = m1l("OT0VOW0HJlQ5JQt1EjghAnUaLCALdQIoPx08GyNtATNUOSULdTEJF1E=", "nUtMM");
        f0I[f1l[18]] = m2lI("edwQLeONPQclNxWUb27/t8rFB+gWfNjEvUAa4Zfo0/R0j1U3KhImmzrjUCLuqWDg6EH0G4SW+dU=", "tgLJs");
        f0I[f1l[19]] = m1l("IAA0CwlXDDgdTAQJOBcYWlllWR8SCSMaBFcfORwCVwQ+FgceBjZZChgacRYfHho4ClM=", "whQyl");
        f0I[f1l[20]] = m1l("IQ0qDEEfFmsMCRNFJRkME0UkHkEVBDIcBFtTbAtBEQ0kCxVJ", "veKxa");
        f0I[f1l[21]] = m2lI("FitSGCVFAwM86UBfr9D19x/2NibvF6DKrMd2QXID6TLRX4seI/DQ063o3jGtj6fBA0HqLOs6Z02Gux1pHKcgZg==",
                "wbUkv");
        f0I[f1l[22]] = m1l("LSM5CzFaLigHLRMocB88Gzs/BnkILiMNNBgnNRt5G2s8DS8fOX0JOg4iPwZ5CCI2BDxF", "zKPhY");
        f0I[f1l[23]] = m0I("z13Xv5GHGP7WC2+WYv39T+3urhKILaG+Nx6NexC96OLHJV7ZcNuC3JIKvji4g3rx", "gmqqx");
        f0I[f1l[24]] = m2lI("IfOB2u6Mun+oaAudIYaOUqNpZOYlQE9v", "etzcE");
        f0I[f1l[25]] = m2lI(
                "pAgOYtfo/KfX9j2ucqpSc6smDo/1GbnA4z8aO3hP2aD2IxwrunTx0y9XeOnASaikOvDrLPUYYXVB5sU1YOJzmkpVLQ7R94WdMHBb+vXbsv5Nk0eyvRlXsg==",
                "MTvaD");
        f0I[f1l[26]] = m2lI("/TVvXx3IErUYFDzua4OA18G2gSg52QLow3CPr69+xJbMkXTyBS1keCG1VPzQJSXYgJHIE9+A1b9YnDTU6wYtMw==",
                "QYLHR");
        f0I[f1l[27]] = m0I("MM2+sqt8W/kCJVZZ4arp35LrAX1IRPkQOYa4e6/jMAQ1tTJuL86X2I9UOjKwoiabznuHJbY3ogg=", "UlQSk");
        f0I[f1l[7]] = m2lI("Cf6N5mya/5KkhookR5KQsegRGLg4gT5f/R80Zha54Hjs4O+7yMZ08O45ukn6T2pxEvxM4ry3s3TXn4bmlXUcHQ==",
                "elVkr");
        f0I[f1l[28]] = m1l(
                "Jxg8RTkQHzdFPxVQLQ01UxUhETUdFDwBcBERKxc1H1ApACIYUDAWcAcYPEUjEh08RTEAUC4NORAYeRY4HAQ+ED5TADwXO0w=",
                "spYeP");
        f0I[f1l[29]] = m1l("Ly82JWwPJiRxOBAidz8tFSJ3PipYMz80bBYoJTUlG2cxMC8MLjg/bBchdyUkHWc1PS0bLHcwPhUoJShz", "xGWQL");
        f0I[f1l[30]] = m2lI(
                "g4GLak/p+Mnozn2aqbtcrwOvncQ8dV9ioM7LVe2OuLsgIVdBdolr7WR7+Ab9J0qMfcKu6w4wLJhL7mo3xww1WnDDpqAlRfJPRpj/L7C2geJThwNKc4FnGE1chHctsZRD",
                "eVXCB");
        f0I[f1l[31]] = m1l(
                "AD4dCwN3OxsMSzA/Ag0YdzdUDgIvMxBIGzgkAAEEOXYbDks/MxUEHz92ARgEOXYXBwc7MxccAjkxVAkFdzkGCks4MFQYBCAzBlc=",
                "WVthk");
        f0I[f1l[32]] = m1l("IwYQFDFUGRwWKRsAWQQtFRpZHjcXHBwWKhEdWQMxEU4dBTgDThgZPVQdDRguVB0JEjwQThYReRVODhI4BAEXSA==",
                "tnywY");
        f0I[f1l[33]] = m1l("IwsVciEKChtyJwULFTxsCgwDPycKFgNyPx8NDj5sBw0UN3M=", "kdbRL");
    }


    public static void main(String[] strArr) {
        System.out.println(f0I[f1l[0]]);
        System.out.println(f0I[f1l[1]]);
        System.out.println(f0I[f1l[2]]);
        StringBuilder sb = new StringBuilder();
        Scanner scanner = new Scanner(System.in);
        while (sb.length() != answer.length()) {
            int nextInt = new Random().nextInt(questions.size());
            String lllllllllllIIll = questions.get(nextInt);
            System.out.println(lllllllllllIIll);
            String nextLine = scanner.nextLine();
            if (!nextLine.equals(f0I[f1l[3]])) {
                sb.append(lllllllllllIIll.charAt(nextInt - Integer.parseInt(nextLine)));
            }
        }
        scanner.close();
        if (String.valueOf(sb).equals(answer)) {
            System.out.println(FLAG);
            return;
        }
        System.out.println(f0I[f1l[4]]);
    }
}
```

Let's take a look at some other simplifiable functions.

For example, this function is only called once in the static block and just fills up the `f1l` array with numbers, so let's rename both the function and array to something more fitting.
```java
private static void lII() {
    f1l = new int[35];
    f1l[0] = 0;
    f1l[1] = 1;
    f1l[2] = 2;
    f1l[3] = 3;
    f1l[4] = 4;
    f1l[5] = 5;
    f1l[6] = 6;
    f1l[7] = 27;
    f1l[8] = 7;
    f1l[9] = 8;
    f1l[10] = 9;
    f1l[11] = 10;
    f1l[12] = 11;
    f1l[13] = 12;
    f1l[14] = 13;
    f1l[15] = 14;
    f1l[16] = 15;
    f1l[17] = 16;
    f1l[18] = 17;
    f1l[19] = 18;
    f1l[20] = 19;
    f1l[21] = 20;
    f1l[22] = 21;
    f1l[23] = 22;
    f1l[24] = 23;
    f1l[25] = 24;
    f1l[26] = 25;
    f1l[27] = 26;
    f1l[28] = 28;
    f1l[29] = 29;
    f1l[30] = 30;
    f1l[31] = 31;
    f1l[32] = 32;
    f1l[33] = 33;
    f1l[34] = 34;
}
// same as
private static void init_numbers() {
    numbers = new int[]{0, 1, 2, 3, 4, 5, 6, 27, 7, 8, 9, 10, 11,
            12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 
            25, 26, 28, 29, 30, 31, 32, 33, 34};
}
```

We also have the other array, `f0I`, that gets filled through another large function. For now, we'll ignore that function and the decryption function it uses, but printing out `f0I` at the start of `main` shows that it just contains all the strings used in the program, including all the questions.

```java
...
public static void main(String[] strArr) {
        System.out.println(Arrays.toString(f0I));
...
```
```
[Beware! I am **LUKE SMITH**! Creator of FOMO!, I will ask you a series of questions, and at the end if you answer them ALL correctly, you might get flag., If you would like you can skip a question by saying SKIP., SKIP, WRONG! LEAVE!, FLAG, 6a4343aa3cb4cfc411, How many points to reset valor rank?, What is the full name of the final boss in the last wish?, Who was the hunter vanguard before cayde-6?, What is the name of the city on neptune?, What grenade suppresses targets?, What perk used to be exclusive to vault of glass weapons, but now can roll on root of nightmares weapons?, Which weapon foundry is known for its liquid ammo?, Which color was the dead orbit faction most closely associated with?, How many times has banshee, the gunsmith, been reset?, What is the full name version of the EDZ?, During a weak curse week, where is petra venj located?, Where did saint-14 search when looking for osiris?, What is the name of cayde-6's ghost?, Which perk grants bonus damage when surrounded by enemies?, Which exotic weapon resembles a lever-action rifle?, Which weapon foundry tried bribing shaxx?, Who does xur work for?, How many oracles spawn during the 3rd round of oracles during a phase against Atheon?, Which clan completed the scourge of the past raid first?, Which ritual playlist is the drifter associated with?, Which seasonal event featured arbalest as its exotic weapon?, The icon of the extended barrel perk is the same as which shotgun perk?, What was the name of the nordic faction of the black armory?, Which augment allows players to interact with panels by shooting them in the deep stone crypt?, Which mod gives a fixed portion of health upon collecting an orb of power?, Which weapon stat increases the draw and stow speed of a weapon?, How many known ahamkara still live?]
```

Here's what the program, with cleaned up names, looks like now:

```java
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Main {

    private static String[] strings = null;
    private static int[] numbers = null;
    public static ArrayList<String> questions;

    static {
        init_numbers();
        init_strings();
        String[] strArr = new String[numbers[7]];
        strArr[numbers[0]] = strings[numbers[8]];
        strArr[numbers[1]] = strings[numbers[9]];
        strArr[numbers[2]] = strings[numbers[10]];
        strArr[numbers[3]] = strings[numbers[11]];
        strArr[numbers[4]] = strings[numbers[12]];
        strArr[numbers[5]] = strings[numbers[13]];
        strArr[numbers[6]] = strings[numbers[14]];
        strArr[numbers[8]] = strings[numbers[15]];
        strArr[numbers[9]] = strings[numbers[16]];
        strArr[numbers[10]] = strings[numbers[17]];
        strArr[numbers[11]] = strings[numbers[18]];
        strArr[numbers[12]] = strings[numbers[19]];
        strArr[numbers[13]] = strings[numbers[20]];
        strArr[numbers[14]] = strings[numbers[21]];
        strArr[numbers[15]] = strings[numbers[22]];
        strArr[numbers[16]] = strings[numbers[23]];
        strArr[numbers[17]] = strings[numbers[24]];
        strArr[numbers[18]] = strings[numbers[25]];
        strArr[numbers[19]] = strings[numbers[26]];
        strArr[numbers[20]] = strings[numbers[27]];
        strArr[numbers[21]] = strings[numbers[7]];
        strArr[numbers[22]] = strings[numbers[28]];
        strArr[numbers[23]] = strings[numbers[29]];
        strArr[numbers[24]] = strings[numbers[30]];
        strArr[numbers[25]] = strings[numbers[31]];
        strArr[numbers[26]] = strings[numbers[32]];
        strArr[numbers[27]] = strings[numbers[33]];
        questions = new ArrayList<>(Arrays.asList(strArr));
    }

    public static String FLAG = System.getenv(strings[numbers[5]]);
    public static String answer = strings[numbers[6]];

    private static String decrypt_des(String a, String b) {
        try {
            SecretKeySpec spec = new SecretKeySpec(Arrays.copyOf(
                    MessageDigest.getInstance("MD5").digest(b.getBytes(StandardCharsets.UTF_8)),
                    numbers[9]),
                    "DES");
            Cipher des = Cipher.getInstance("DES");
            des.init(numbers[2], spec);
            return new String(
                    des.doFinal(Base64.getDecoder().decode(a.getBytes(StandardCharsets.UTF_8))),
                    StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static String decrypt_xor(String a, String b) {
        String str = new String(Base64.getDecoder().decode(a.getBytes(StandardCharsets.UTF_8)),
                StandardCharsets.UTF_8);
        StringBuilder sb = new StringBuilder();
        char[] b_chars = b.toCharArray();
        int j = numbers[0];
        char[] a_chars = str.toCharArray();
        int length = a_chars.length;
        int i = numbers[0];
        while (i < length) {
            sb.append((char) (b_chars[j % b_chars.length] ^ a_chars[i]));
            j++;
            i++;
        }
        return String.valueOf(sb);
    }

    private static String decrypt_blowfish(String a, String b) {
        try {
            SecretKeySpec spec = new SecretKeySpec(
                    MessageDigest.getInstance("MD5").digest(b.getBytes(StandardCharsets.UTF_8)),
                    "Blowfish");
            Cipher blowfish = Cipher.getInstance("Blowfish");
            blowfish.init(numbers[2], spec);
            return new String(
                    blowfish
                            .doFinal(Base64.getDecoder()
                                    .decode(a.getBytes(StandardCharsets.UTF_8))),
                    StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static void init_numbers() {
        numbers = new int[] { 0, 1, 2, 3, 4, 5, 6, 27, 7, 8, 9, 10, 11,
                12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
                25, 26, 28, 29, 30, 31, 32, 33, 34 };
    }

    private static void init_strings() {
        strings = new String[numbers[34]];
        strings[numbers[0]] = decrypt_des("M/b6LLu69fV+83nC8P7cm3NFbwzMtVJqvcj4KgrkM1oP6WezWoyCF0V4emNjq8Lr",
                "RGFHA");
        strings[numbers[1]] = decrypt_xor(
                "K2kHIgEOaRE4BkIwHz5NA2kDLh8LLANrAgRpAT4IET0ZJAMRZVAqAwZpET9NFiEVawgMLVAiC0IwHz5NAycDPAgQaQQjCA9pMQchQiofOR8HKgQnFE5pCSQYQiQZLAUWaRcuGUIvHCoKTA==",
                "bIpKm");
        strings[numbers[2]] = decrypt_blowfish(
                "dd6iCFEwZ2klnD1az2dXLSR/NK9T/iR3X0il3BwwlhUk9L5OG6hymVElvLh4wIS8Dn/DOqWtgef2jSmMWRtjMw==",
                "djaDa");
        strings[numbers[3]] = decrypt_des("E5g1tM7xB/I=", "LZHyW");
        strings[numbers[4]] = decrypt_blowfish("4AdI/0mTyFRnfr75NpLgag==", "RpPkm");
        strings[numbers[5]] = decrypt_blowfish("L0t7r/fDEXI=", "OGtWu");
        strings[numbers[6]] = decrypt_xor("ZiNmXH1jIzNcKjJ2MQkqZHNj", "PBRoI");
        strings[numbers[8]] = decrypt_blowfish("YYacupVSSuGFdB7+vShn5fbMz8Bu8XagjZZEXDsbAtODn/xfwfzIDA==", "qUEDX");
        strings[numbers[9]] = decrypt_xor(
                "OSw0GkoHN3UaAgtkMxsGAmQ7DwcLZDoIShosME4MByo0AkoMKyYdSgcqdRoCC2Q5DxkaZCIHGQZ7",
                "nDUnj");
        strings[numbers[10]] = decrypt_des("4uK7g3MKtHnoNDeRWLb6yPq0yoKwxIQgaQdWnXmUXey5u3eWZk7B6qGCzd55gtMC",
                "vOgjG");
        strings[numbers[11]] = decrypt_des("eOVkXQG4iWlaMF9FrJ2BHY4La192LJOfl5k9i+LuNJ+Lv3/CzEXt7qVOQuoKXX9o",
                "PUPyS");
        strings[numbers[12]] = decrypt_des("UHXIyKrSgcVHARWFDRZ78RFyxDhz8uNAvzJizKPOHx5fG5uBbBCB3A==", "YWDUY");
        strings[numbers[13]] = decrypt_des(
                "F+5EeR6FRrQiFFbVB1ANdxhJrUxRPVyhkqwgws0XAmXu/pvVbQaL9qffvgK+u0kOFQBzqlPPAvuUGdTDiY2PcBqc6xJ4eElc/HgnYNXn436EAs1MB8o5UIJo0SMBexqsFQBzqlPPAvvH9N1RmFJ8BQ==",
                "RsvRt");
        strings[numbers[14]] = decrypt_des(
                "DVw06+nt0YxuTCDJRfDhD5K1m5FvyrpFkmUfnNiGx6j2yE/y96DUB7MUFbjn3T4Xlt1F2OC5EIw=",
                "sDwKZ");
        strings[numbers[15]] = decrypt_xor(
                "DykMOhh4Igo1HyphEjgDeDUNPFA8JAQ9UDczBzAEeCcEOgQxLgt5HTcyEXkTNC4WPBwhYQQqAzciDDgEPSVFLhksKVo=",
                "XAeYp");
        strings[numbers[16]] = decrypt_xor(
                "Hgc1bxk3BjtvAD8FJzxUPgkxbxY3BjEnETNEYjscM0glOholBSs7HHpIICoROEgwKgczHH0=", "VhBOt");
        strings[numbers[17]] = decrypt_xor("OT0VOW0HJlQ5JQt1EjghAnUaLCALdQIoPx08GyNtATNUOSULdTEJF1E=", "nUtMM");
        strings[numbers[18]] = decrypt_blowfish(
                "edwQLeONPQclNxWUb27/t8rFB+gWfNjEvUAa4Zfo0/R0j1U3KhImmzrjUCLuqWDg6EH0G4SW+dU=",
                "tgLJs");
        strings[numbers[19]] = decrypt_xor(
                "IAA0CwlXDDgdTAQJOBcYWlllWR8SCSMaBFcfORwCVwQ+FgceBjZZChgacRYfHho4ClM=", "whQyl");
        strings[numbers[20]] = decrypt_xor("IQ0qDEEfFmsMCRNFJRkME0UkHkEVBDIcBFtTbAtBEQ0kCxVJ", "veKxa");
        strings[numbers[21]] = decrypt_blowfish(
                "FitSGCVFAwM86UBfr9D19x/2NibvF6DKrMd2QXID6TLRX4seI/DQ063o3jGtj6fBA0HqLOs6Z02Gux1pHKcgZg==",
                "wbUkv");
        strings[numbers[22]] = decrypt_xor(
                "LSM5CzFaLigHLRMocB88Gzs/BnkILiMNNBgnNRt5G2s8DS8fOX0JOg4iPwZ5CCI2BDxF", "zKPhY");
        strings[numbers[23]] = decrypt_des("z13Xv5GHGP7WC2+WYv39T+3urhKILaG+Nx6NexC96OLHJV7ZcNuC3JIKvji4g3rx",
                "gmqqx");
        strings[numbers[24]] = decrypt_blowfish("IfOB2u6Mun+oaAudIYaOUqNpZOYlQE9v", "etzcE");
        strings[numbers[25]] = decrypt_blowfish(
                "pAgOYtfo/KfX9j2ucqpSc6smDo/1GbnA4z8aO3hP2aD2IxwrunTx0y9XeOnASaikOvDrLPUYYXVB5sU1YOJzmkpVLQ7R94WdMHBb+vXbsv5Nk0eyvRlXsg==",
                "MTvaD");
        strings[numbers[26]] = decrypt_blowfish(
                "/TVvXx3IErUYFDzua4OA18G2gSg52QLow3CPr69+xJbMkXTyBS1keCG1VPzQJSXYgJHIE9+A1b9YnDTU6wYtMw==",
                "QYLHR");
        strings[numbers[27]] = decrypt_des(
                "MM2+sqt8W/kCJVZZ4arp35LrAX1IRPkQOYa4e6/jMAQ1tTJuL86X2I9UOjKwoiabznuHJbY3ogg=",
                "UlQSk");
        strings[numbers[7]] = decrypt_blowfish(
                "Cf6N5mya/5KkhookR5KQsegRGLg4gT5f/R80Zha54Hjs4O+7yMZ08O45ukn6T2pxEvxM4ry3s3TXn4bmlXUcHQ==",
                "elVkr");
        strings[numbers[28]] = decrypt_xor(
                "Jxg8RTkQHzdFPxVQLQ01UxUhETUdFDwBcBERKxc1H1ApACIYUDAWcAcYPEUjEh08RTEAUC4NORAYeRY4HAQ+ED5TADwXO0w=",
                "spYeP");
        strings[numbers[29]] = decrypt_xor(
                "Ly82JWwPJiRxOBAidz8tFSJ3PipYMz80bBYoJTUlG2cxMC8MLjg/bBchdyUkHWc1PS0bLHcwPhUoJShz",
                "xGWQL");
        strings[numbers[30]] = decrypt_blowfish(
                "g4GLak/p+Mnozn2aqbtcrwOvncQ8dV9ioM7LVe2OuLsgIVdBdolr7WR7+Ab9J0qMfcKu6w4wLJhL7mo3xww1WnDDpqAlRfJPRpj/L7C2geJThwNKc4FnGE1chHctsZRD",
                "eVXCB");
        strings[numbers[31]] = decrypt_xor(
                "AD4dCwN3OxsMSzA/Ag0YdzdUDgIvMxBIGzgkAAEEOXYbDks/MxUEHz92ARgEOXYXBwc7MxccAjkxVAkFdzkGCks4MFQYBCAzBlc=",
                "WVthk");
        strings[numbers[32]] = decrypt_xor(
                "IwYQFDFUGRwWKRsAWQQtFRpZHjcXHBwWKhEdWQMxEU4dBTgDThgZPVQdDRguVB0JEjwQThYReRVODhI4BAEXSA==",
                "tnywY");
        strings[numbers[33]] = decrypt_xor("IwsVciEKChtyJwULFTxsCgwDPycKFgNyPx8NDj5sBw0UN3M=", "kdbRL");
    }

    public static void main(String[] strArr) {
        System.out.println(strings[numbers[0]]);
        System.out.println(strings[numbers[1]]);
        System.out.println(strings[numbers[2]]);
        StringBuilder sb = new StringBuilder();
        Scanner scanner = new Scanner(System.in);
        while (sb.length() != answer.length()) {
            int questionIndex = new Random().nextInt(questions.size());
            String nextQuestion = questions.get(questionIndex);
            System.out.println(nextQuestion);
            String nextLine = scanner.nextLine();
            if (!nextLine.equals(strings[numbers[3]])) {
                sb.append(nextQuestion.charAt(questionIndex - Integer.parseInt(nextLine)));
            }
        }
        scanner.close();
        if (String.valueOf(sb).equals(answer)) {
            System.out.println(FLAG);
            return;
        }
        System.out.println(strings[numbers[4]]);
    }
}
```
Now that we're finally done cleaning it up, let's finally look at the main function logic:
```java
public static void main(String[] strArr) {
    System.out.println(strings[numbers[0]]);
    System.out.println(strings[numbers[1]]);
    System.out.println(strings[numbers[2]]);
    StringBuilder sb = new StringBuilder();
    Scanner scanner = new Scanner(System.in);
    while (sb.length() != answer.length()) {
        int questionIndex = new Random().nextInt(questions.size());
        String nextQuestion = questions.get(questionIndex);
        System.out.println(nextQuestion);
        String nextLine = scanner.nextLine();
        if (!nextLine.equals(strings[numbers[3]])) {
            sb.append(nextQuestion.charAt(questionIndex - Integer.parseInt(nextLine)));
        }
    }
    scanner.close();
    if (String.valueOf(sb).equals(answer)) {
        System.out.println(FLAG);
        return;
    }
    System.out.println(strings[numbers[4]]);
}
```

First, three strings are printed, which is just the introduction paragraph.
```
Beware! I am **LUKE SMITH**! Creator of FOMO!
I will ask you a series of questions, and at the end if you answer them ALL correctly, you might get flag.
If you would like you can skip a question by saying SKIP.
```

Next, we initialize a StringBuilder and a Scanner, and enter a loop.
Inside the loop, a random question is chosen, then if we don't enter `SKIP`, the character at the index `questionIndex - int(input)` of the question string itself is appended to the StringBuilder. 

Finally, after the StringBuilder has the same length as the answer, the loop ends, and a final check is made, and if the built string is the same as `answer`, we get the flag.

Since we have access to the full decompiled file, we can easily just print out the value of `answer`:
```java
System.out.println(answer);
```
```
6a4343aa3cb4cfc411
```
Now all we have to do to construct this string is to keep skipping until we reach a question containing the next character, then calculate the proper integer to submit for that character.

I'm gonna skip extracting the questions, as its just the same thing, printing out and copy pasting.

Here's what my final solve script ended up looking like:
```python
from pwn import remote
# nc 213.133.103.186 7448
r = remote("213.133.103.186", 7448)

questions = ["How many points to reset valor rank?",
 "What is the full name of the final boss in the last wish?",
 "Who was the hunter vanguard before cayde-6?",
 "What is the name of the city on neptune?",
 "What grenade suppresses targets?",
 "What perk used to be exclusive to vault of glass weapons, but now can roll on root of nightmares weapons?",
 "Which weapon foundry is known for its liquid ammo?",
 "Which color was the dead orbit faction most closely associated with?",
 "How many times has banshee, the gunsmith, been reset?",
 "What is the full name version of the EDZ?",
 "During a weak curse week, where is petra venj located?",
 "Where did saint-14 search when looking for osiris?",
 "What is the name of cayde-6's ghost?",
 "Which perk grants bonus damage when surrounded by enemies?",
 "Which exotic weapon resembles a lever-action rifle?",
 "Which weapon foundry tried bribing shaxx?",
 "Who does xur work for?",
 "How many oracles spawn during the 3rd round of oracles during a phase against Atheon?",
 "Which clan completed the scourge of the past raid first?",
 "Which ritual playlist is the drifter associated with?",
 "Which seasonal event featured arbalest as its exotic weapon?",
 "The icon of the extended barrel perk is the same as which shotgun perk?",
 "What was the name of the nordic faction of the black armory?",
 "Which augment allows players to interact with panels by shooting them in the deep stone crypt?",
 "Which mod gives a fixed portion of health upon collecting an orb of power?",
 "Which weapon stat increases the draw and stow speed of a weapon?",
 "How many known ahamkara still live?"]
key = "6a4343aa3cb4cfc411"

for c in key:
    for q in questions:
        if c in q:
            print(c, q)

r.recvuntil(b'SKIP.\n')
build = ""
while len(build) != len(key):
    question = r.recvline().decode().strip()
    q_index = questions.index(question)
    wanted = key[len(build)]
    if wanted not in question:
        r.sendline(b"SKIP")
        continue
    print(question, q_index, wanted, build)
    wanted_index = question.index(wanted)
    r.sendline(str(q_index - wanted_index).encode())
    build += wanted
r.interactive()
```
flag: `bucket{D35T1NY_F0M0_0c0f34b03}`

[Back to TOC](#toc)