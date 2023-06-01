---
title: "DeadSecCTF 2023 - LCG Writeup"
date: 2023-05-22T20:37:02-05:00
tags: ["2023", "DeadSecCTF", "crypto"]
mathjax: true
summary: "Cracking LCGs and solving bivariate equations"
---

Had a lot of fun playing DeadSecCTF this past weekend, here's a writeup for the challenge `LCG` in the `crypto` category.

## Description
> Can you recover the message?
>
> [chall.py](#chall.py)
> [out.txt](#out.txt)

filename=chall.py
```python 
import random
from Crypto.Util.number import *
import gmpy2

class LCG:
    def __init__(self, a, c, m, seed):
        self.seed = seed
        self.multiplier = a
        self.increment = c
        self.modulus = m
    
    def next(self):
        self.seed = (self.multiplier*self.seed + self.increment) % self.modulus
        return self.seed
    
    def __str__(self):
        return ", \n".join(map(str, [self.seed, self.multiplier, self.increment, self.modulus]))

def gen_primes(PRIME_SIZE):
    lcg = LCG(random.getrandbits(PRIME_SIZE//4), random.getrandbits(PRIME_SIZE//4), random.getrandbits(PRIME_SIZE//4), random.getrandbits(PRIME_SIZE//4))    
    
    r1 = random.getrandbits(PRIME_SIZE//4)
    p = r1 << ((PRIME_SIZE*3)//4)
    for _ in range(3):
        p = p | (lcg.next() << (PRIME_SIZE*(2 - _))//4)
    
    r2 = random.getrandbits(PRIME_SIZE//4)
    q = r2 << ((PRIME_SIZE*3)//4)
    for _ in range(3):
        q = q | (lcg.next() << (PRIME_SIZE*(2 - _))//4)
        
    return lcg, p, q

while True:
    lcg, p, q = gen_primes(512)
    if gmpy2.is_prime(p) and gmpy2.is_prime(q) and gmpy2.gcd(lcg.multiplier, lcg.modulus) == 1:
        break

n = p * q
e = 65537
flag = b''
c = pow(bytes_to_long(flag), e, n)
print(f"n: {n}")
print(f"ct: {c}")
print("Hint:")
print([lcg.next() for _ in range(6)])
```

filename=out.txt
```text
n: 21650447514664703683541519919331263390282460469744888634490387443119262785059244453207960009159682413880209329211270923006772751974531441721185385117102290236861537255410467283919771278372439649180599019262938453870697814603482585923290155250911013461308363715765472530666765831515068628482160014076801654521
ct: 13119263762666966865889936515574328574427409372529276945448580211178603280310168998625170993340627371121987348265853339044876374353275949199559703791552498065356283102983556442205370872035849628351308403614183495058585452791359893308496622183117417598843112140605324797308265631765340150190302633479928043831
Hint:
[29861218495988619292793747700054834633, 80515105569441253388392760789853242718, 146729873894560318431962601721322042903, 147107348315338274128018394071748133508, 166087854880219056255852907837404957463, 210401924703541158042341118614982072753]
```

So here's the main setup:
- We're given a basic RSA encrypted flag with `n` and `ct`.
- We also have an LCG that generates the lower 3/4ths of `p` and `q` (the upper 1/4th uses a different PRNG).
- We're given 6 outputs of the LCG.
  
This means that somehow, we first need to completely recover the LCG, step backwards to find the lower bits of the primes, then factor `n` to break the RSA encryption and get the flag. Let's get started!

## Breaking LCGs: The Easy Part
Let's start by cracking the LCG first. There's plenty of documentation online on solving LCGs with 0 information, but I'll try to walk through it here.

### Finding the modulus
First we need to recover the modulus of the LCG. To do this, we can use a simple trick to recover multiples of the modulus and `gcd` them together to find either the modulus itself or a low multiple.

Let's set up the following equations and define $S_n$ as the $n$th output of the LCG, as well as $a$ as the multiplier, $c$ as the increment, and $m$ as the modulus:

$$
\begin{align}
S_n &= aS_{n-1} + c &\mod m \\\\
T_n &= S_{n+1} - S_n &\mod m\\\\
\\\\
T_0 &= S_1 - S_0 \\\\
T_0 &= aS_0 + c - S_0 &\mod m \\\\
T_1 &= S_2 - S_1 \\\\
T_1 &= aS_1 + c - S_1 &\mod m \\\\
\end{align}
$$

Between consecutive elements in $T$, we can notice this pattern:

$$
\begin{align}
T_n &= aS_n + c - S_n &\mod m \\\\
T_n &= a(aS_{n-1} + c) + c - (aS_{n-1} + c) &\mod m \\\\
T_n &= a^2S_{n-1} + ac + c - aS_{n-1} - c &\mod m \\\\
T_n &= a(aS_{n-1} + c - S_{n-1}) &\mod m \\\\
T_n &= aT_{n-1} &\mod m \\\\
\end{align}
$$

Meaning that $T$ forms its own LCG with the same modulus and multiplier but no increment. Witht this new LCG, we can now easily find the modulus by just multiplying different items in $T$ to get differences that are $k\cdot m$ for some integer $k$.

$$
\begin{align}
T_1 &= aT_0 &\mod m \\\\
T_2 &= aT_1 &\mod m \\\\
\\\\
T_1^2 &= a^2T_0^2 &\mod m \\\\
T_2T_0 &= (aT_1)(T_0) \\\\
&= (a(aT_0))T_0 \\\\
&= a^2T_0^2 &\mod m \\\\
\\\\
&\boxed{T_1^2 - T_2T_0 = 0 \mod m = k\cdot m}& \\\\
\end{align}
$$

If we gather enough of these, we can just `gcd` them together to find the modulus. Unfortunately, the output is chosen so that we get a multiple of the modulus, but since we know the number has to be around 128 bits, we can easily guess that it is a factor of $5$ too large.

```python
from math import gcd
S = [29861218495988619292793747700054834633, 80515105569441253388392760789853242718, 146729873894560318431962601721322042903, 147107348315338274128018394071748133508, 166087854880219056255852907837404957463, 210401924703541158042341118614982072753]

Ts = [S[i+1] - S[i] for i in range(len(S)-1)]
Us = [abs(Ts[i+2] * Ts[i] - Ts[i+1] * Ts[i+1]) for i in range(len(Ts)-2)]

M = abs(gcd(*Us))
print(M, int(M).bit_length())
>>> 1224107675531864356603669618231679702075 130
```
```
1224107675531864356603669618231679702075/5 = 
244821535106372871320733923646335940415
```

Nice! We've recovered the modulus, so we can move on to part 2, recovering the multiplier.

### Recovering the multiplier
Let's go back to the $T$ LCG earlier, since the multiplier is the only unknown there.
We should be able to easily recover $a$ like so:

$$
\begin{align}
T_1 &= aT_0 &\mod m \\\\
a &= T_1T_0^{-1} &\mod m \\\\
\end{align}
$$

But if we try this out in Python, we get an error...

```python
# continuing from before
Ts = [T % M for T in Ts]
T0 = Ts[0]
T1 = Ts[1]

A = (T1 * pow(T0, -1, M)) % M
print(A)
```
```
Traceback (most recent call last):
  File "test.py", line 16, in <module>
    A = (T1 * pow(T0, -1, M)) % M
              ^^^^^^^^^^^^^^
ValueError: base is not invertible for the given modulus
```

Unfortunately, our $T$ values aren't coprime with $m$, so we can't just take the modular inverse. Thankfully, we can still recover $a$ very simply by the following identity:

$$
\begin{align}
g &= gcd(T_1, T_0, m) \\\\
T_1 &= aT_0 &\mod m \\\\
\frac{T_1}{g} &= a\frac{T_0}{g} &\mod \frac{m}{g} \\\\
a &= \frac{T_1}{g}/\frac{T_0}{g} &\mod \frac{m}{g} \\\\
\end{align}
$$

(Just a note, if $a$ is too small after this calculation, we can just add $m/g$ to it until it properly satisfies the $T$ LCG)

```python
# continuing from before
Ts = [T % M for T in Ts]
T0 = Ts[0]
T1 = Ts[1]

G = gcd(M, gcd(T1, T0))

M_g = M // G
T1_g = T1 // G
T0_g = T0 // G

A = (T1_g * pow(T0_g, -1, M_g)) % M_g
print(A, T1 == T0 * A % M)
>>> 761998600219052390751011947734077631 True
```

### Calculating the increment
Now the last part is the easiest, all we have to do is

$$
\begin{align}
S_1 &= aS_0 + c &\mod m \\\\
c &= S_1 - aS_0 &\mod m \\\\
\end{align}
$$

```python
C = S[1] - S[0] * A % M
print(C)
>>> 166465905477134684675482981011786701870
```

### Going backwards
Now that we have all the LCG parameters, we can simply just step backwards to get the low bits of both primes.

```python
# inside LCG class
    self.inv_mult = int(pow(a, -1, m))

def prev(self):
    self.seed = (self.inv_mult * (self.seed - self.increment)) % self.modulus
    return self.seed


lcg = LCG(A, C, M, S[0])
print(lcg)
for _ in range(7):
    print(lcg.prev())

PRIME_SIZE = 512
p_low = 0
for _ in range(3):
    p_low = p_low | (lcg.next() << (PRIME_SIZE*(2 - _))//4)

q_low = 0
for _ in range(3):
    q_low = q_low | (lcg.next() << (PRIME_SIZE*(2 - _))//4)

print(p_low, p_low.bit_length())
print(q_low, q_low.bit_length())
```
```
13840502788412896965686804480699888011094508190835972222953823231587129208721991127413360932081103349687895622036439 383
7320629874514098189615003088850781500246108104301157430019735253104825244834103750925350260034317414424601821524399 382
```

## Actually just Univariate in disguise? :warning: Sage & math ahead :warning:
Now we have the low bits of both primes, we can set up a bivariate equation which should give us the high bits like so:

$$
\begin{align}
k &= 384 \text{(offset for high bits)} \\\\
\\\\
f &= (p_{low} + p_{high}2^k)(q_{low} + q_{high}2^k) - n \\\\
\end{align}
$$

But actually, because these equations are over the integers, we can use the `monic` and `small_roots` functions in SageMath to 
create a univariate polynomial with an easy solution!

```python
P.<x> = PolynomialRing(Zmod(n))
p_small = 13840502788412896965686804480699888011094508190835972222953823231587129208721991127413360932081103349687895622036439 # from above
f = p_small + x*2^384
f = f.monic()
show(f)
p_high = f.small_roots(beta=0.4, X=2^128)[0] # beta should be less than 1/2
print(p_high)
```
```
x + <very big number here>
51124072313420104261781687898895862037 # our p_high!
```

In fact, when I was solving this challenge originally, I forgot that `monic` existed, and kept trying to jank some method for `small_roots`.
Eventually, I stumbled upon [this implementation](https://github.com/ubuntor/coppersmith-algorithm/blob/main/coppersmith.sage) which I used to solve (It implements [this paper](http://www.crypto-uni.lu/jscoron/publications/bivariate.pdf)).

It creates a bunch of monomials from the original bivariate polynomial and uses LLL to solve for small roots. If you want specifics, I recommended reading the paper and checking out the code.

Anyway, the solve implementation is the same, just call the provided `coron` method with the correct parameters.

filename=solve.py
```python
X = 2^(int(p_low).bit_length()+1)
Y = 2^(int(q_low).bit_length()+1)
P.<x,y> = PolynomialRing(ZZ)
KNOWN_SIZE = PRIME_SIZE // 4 * 3
poly = (x * 2^KNOWN_SIZE + p_low) * (y * 2^KNOWN_SIZE + q_low) - N

p_high, q_high = coron(poly, X, Y, debug=True)[0]
p = p_high * 2^KNOWN_SIZE + p_low
q = q_high * 2^KNOWN_SIZE + q_low
print(p, q)
```
```
2014391014078298385848382718603864559304182057702332106747947726391450683922565863407711433231851216065404029594338847221099546815781164798298144058780631 10747887258904919568852319173708167129975394787092626003408658827329574207417581519371916706345292847334280224997653414111932233127444601482464256870134191
```

## Flag
Finally, we have recovered $p$ and $q$. All we need to do now is calculate $d$ and decrypt the flag.

filename=solve.py
```python
from Crypto.Util.number import long_to_bytes
phi = (p - 1) * (q - 1)
e = 65537
d = inverse_mod(e, phi)
ct = 13119263762666966865889936515574328574427409372529276945448580211178603280310168998625170993340627371121987348265853339044876374353275949199559703791552498065356283102983556442205370872035849628351308403614183495058585452791359893308496622183117417598843112140605324797308265631765340150190302633479928043831
m = int(pow(ct, d, N))
print(long_to_bytes(m))
```
filename=flag.txt
```
b'Dead{7d19a88ab11151c222a8b}'
```
GG! :smile:

## Closing Thoughts
I had a lot of fun doing this challenge (*cough cough* even if vishi lied about our modulus being wrong *cough cough*), and I feel like I'm actually starting to understand these types of Coppersmith attacks and polynomials a lot more :sunglasses:. 

It's been a long journey since I first started doing CTFs so it's nice to do these challenges where I can see my own progress. I hope you enjoyed reading this writeup, and I'll see you in the next one! :wave: