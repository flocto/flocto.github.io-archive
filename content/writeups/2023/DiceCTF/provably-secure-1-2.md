---
title: "Provably Secure 1 and 2"
date: 2023-02-17T14:54:40-06:00
tags: ["crypto", "dicectf", "2023"]
summary: "Spending way too long making an audioless 5 minute video..."
mathjax: true
---

Wanted to try out something different, so I decided to use Motion Canvas to try and make a video writeup for the 2 easy crypto challs...

Only to end up spending 2 weeks to make a 5 minute video with no audio lol.

Here's a short text writeup for the both of them:

## Provably Secure 1
Server doesn't properly handle checking already encrypted ciphertext, so we can literally just treat it like an encryption/decryption oracle.

We have to guess `m_bit` 128 times depending on which message is encrypted, so just using two unique messages is fine.
Shortcut: use `0` and `1` so we can just cast to int and directly send it to the server.
```py
from pwn import *
from tqdm import tqdm
# nc mc.ax 31493
r = remote('mc.ax', 31493)

for i in tqdm(range(128)):
    r.recvuntil(b'Action:')
    r.sendline(b'1')
    r.recvuntil(b'm0 (16 byte hexstring):')
    r.sendline(b'0'*32)
    r.recvuntil(b'm1 (16 byte hexstring):')
    r.sendline(b'0'*31 + b'1')

    ct = r.recvline().strip()

    r.recvuntil(b'Action:')
    r.sendline(b'2')
    r.recvuntil(b'ct (512 byte hexstring):')
    r.sendline(ct)

    m = r.recvline().strip()
    m = int(m) # 0 or 1

    r.recvuntil(b'Action:')
    r.sendline(b'0')
    r.recvuntil(b'm_bit guess:')
    r.sendline(str(m).encode())

r.interactive()
```

## Provably Secure 2
#### Actual exploitation of encryption scheme, but same setup, just with fatal bug fixed.

There is two keys, so we can split scheme into two seperate functions that occur on the same pair.
Treat encryption and decryption as black box functions: (`r` is random bytes, `m_b` is chosen message)
$$
\begin{align}
E(m_1, m_2) &=& E_1(r), E_2(r \oplus m_b) \newline
D(c_1, c_2) &=& D_1(c_1) \oplus D_2(c_2)
\end{align}
$$


$$
\begin{align}
D_1(E_1(x)) = x \newline
D_2(E_2(x)) = x
\end{align}
$$
We have free control over `m_1`, `m_2` for encryption, and `c_1`, `c_2` for decryption.

However, we don't know `r`.

But consider the following construction where we swap ciphertext pairs:
(apologies for spaghetti but hopefully you get the idea)
$$
\begin{align}
E_1(r_1), E_2(r_1 \oplus m_{b1}) = E(m_1, m_2) \newline
E_1(r_2), E_2(r_2 \oplus m_{b2}) = E(m_1, m_2) 
\end{align}
$$

$$
D(E_1(r_1), E_2(r_2 \oplus m_{b2}))
= D_1(E_1(r_1)) \oplus D_2(E_2(r_2 \oplus m_{b2})) 
= r_1 \oplus (r_2 \oplus m_{b2})
= r_1 \oplus r_2 \oplus m_{b2}
$$

$$
D(E_1(r_2), E_2(r_1 \oplus m_{b1}))
= D_1(E_1(r_2)) \oplus D_2(E_2(r_1 \oplus m_{b1}))
= r_2 \oplus (r_1 \oplus m_{b1})
= r_1 \oplus r_2 \oplus m_{b1}
$$

Notice that if `m_b1` and `m_b2` are the same, then `r_1 \oplus r_2 \oplus m_b1` is the same as `r_1 \oplus r_2 \oplus m_b2`.

So all we have to do is vary one message, and recover `m_bit` based on whether the swapped decryption changes or not.

```py
from pwn import *
from tqdm import tqdm
# nc mc.ax 31497
r = remote('mc.ax', 31497)

for i in tqdm(range(128)):
    r.recvuntil(b'Action:')
    r.sendline(b'1')
    r.recvuntil(b'm0 (16 byte hexstring):')
    r.sendline(b'0'*32)
    r.recvuntil(b'm1 (16 byte hexstring):')
    r.sendline(b'0'*31 + b'1')

    ct1 = r.recvline().strip()

    r.recvuntil(b'Action:')
    r.sendline(b'1')
    r.recvuntil(b'm0 (16 byte hexstring):')
    r.sendline(b'0'*32 )
    r.recvuntil(b'm1 (16 byte hexstring):')
    r.sendline(b'0'*31 + b'2')

    ct2 = r.recvline().strip()

    dt1 = ct1[:512] + ct2[512:]
    dt2 = ct2[:512] + ct1[512:]

    r.recvuntil(b'Action:')
    r.sendline(b'2')
    r.recvuntil(b'ct (512 byte hexstring):')
    r.sendline(dt1)

    m1 = r.recvline().strip()

    r.recvuntil(b'Action:')
    r.sendline(b'2')
    r.recvuntil(b'ct (512 byte hexstring):')
    r.sendline(dt2)

    m2 = r.recvline().strip()
    m = int(m1 != m2)

    r.recvuntil(b'Action:')
    r.sendline(b'0')
    r.recvuntil(b'm_bit guess:')
    r.sendline(str(m).encode())

r.interactive()
```

## Video
Here's the [video](https://www.youtube.com/watch?v=vAcX--GornA&ab_channel=flocto) if you want to watch it, but its basically the same as above with cooler visuals.