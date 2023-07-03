---
title: "UIUCTF 2023 Writeups"
date: 2023-07-02T21:57:50-05:00
tags: ["2023", "misc", "rev", "uiuctf"]
summary: Writeups for UIUCTF 2023, a CTF hosted by UIUC's SIGPwny. Really cool, open-ended challenges, and a fun theme.
---
Once again another banger CTF from SigPwny, including a cool theme that I completely avoided to solve challenges faster. :joy::joy::joy: ~~*(jk the theme was actually cool tho)*~~

Anyway, I ended up solving quite a few challenges in misc/rev, so here's writeups for both vimjails, [geoguessr](#geoguessr-), [pwnykey](#pwnykey), and [Schrodinger's Cat](not done).

# Vimjail 1 (and 1.5)
BTW, as a disclaimer, these vimjail writeups cover a solution that solves both the original and the .5 updated version, and does not cover the cheese that was patched.

Anyway, starting with Vimjail 1, we're given this setup.

filename=vimrc
```text 
set nocompatible
set insertmode

inoremap <c-o> nope
inoremap <c-l> nope
inoremap <c-z> nope
inoremap <c-\><c-n> nope
```
filename=entry.sh
```text
#!/usr/bin/env sh

vim -R -M -Z -u /home/user/vimrc
```

and our goal is to somehow read `/flag.txt`, as expected of a jail.

Connecting to remote (`socat file:$(tty),raw,echo=0 tcp:vimjail1.chal.uiuc.tf:1337`), we're greeted with an empty vim buffer, stuck in insert mode.


The usual escapes `<c-[>` (`<c-` standing for `Ctrl+`) and `Esc` don't work, and neither do any of the mapped out keybinds in the vimrc. We also can't modify the buffer, since we launched with `-M`.

After messing around a bit with random keybinds, we find that both `<c-x>` and `<c-r>` are allowed. `<c-x>`, completion mode, doesn't seem to lead anywhere interesting though, since again, the buffer is unmodifiable.

But interestingly, `<c-r>`, the registers, does actually give us something useful. The normal registers don't do anything, but we do have access to `=`, the expression register. 

The expression register allows us to input expression and it will spit out the result of the expression. For example, in normal Vim, typing `2+2` into the expression register would put `4` into the buffer.

What the expression register is actually doing is treating our input as `vimscript`, then executing it internally and returning the result. This means we basically have free `vimscript` execution, so running `system` should work right?

```text
=system("ls")
E145: Shell commands and some functionality not allowed in rvim
```

Oh right... we also launched with `-Z`

Thankfully, theres [a lot of other functions](https://vimhelp.org/usr_41.txt.html#41.6) we can use that don't trigger rvim's limitations.

We can use `readfile("/flag.txt")` to get the flag, except we don't have any way to see the actual result since it can't get pasted into the buffer. Instead, all we need to do is get an error message to pop up with the result of the `readfile`. There's a lot of ways to do this, but I ended up just using `eval`.

(also `readfile` returns a list but obviously the flag will just be in the first line so we just use `[0]`)
```text
=eval(readfile("/flag.txt")[0])
E121: Undefined variable: n0_3sc4p3_f0r_y0u_8613a322d0eb0628
Press ENTER or type command to continue
E15: Invalid expression: "uiuctf{n0_3sc4p3_f0r_y0u_8613a322d0eb0628}"
Press ENTER or type command to continue
```

This also works for vimjail 1.5.
```text
=eval(readfile("/flag.txt")[0])
E121: Undefined variable: ctr1_r_1s_h4ndy_277d0fde079f49d2
Press ENTER or type command to continue
E15: Invalid expression: "uiuctf{ctr1_r_1s_h4ndy_277d0fde079f49d2}"
Press ENTER or type command to continue
```

# Vimjail 2 (and 2.5
This time theres a bit more limitations. In addition to the previously banned keybinds, all of the following are replaced with `_`.

```text
abcdefghijklmnoprstuvwxyz!@#$%^&*-+=`~{}[]|\;<>,./?
```

We can still access registers thankfully, but it seems we can't execute anything useful since all the built-in functions only use lowercase letters.

Except, given that `q` isn't banned, there's another trick we haven't used yet, [inserting literal characters.](https://learnbyexample.github.io/vim_reference/Insert-mode.html#insert-special-characters)

If we press `<c-q>` (`<c-v` is bound to paste) while inside the expression register, we can then type a letter like `a`.
Since we're inserting a character, the vimrc replacement doesn't apply, the `^a` gets evaluated as `a`, and we just got `a` into the expression register!

```
(in expression register)
= 
(press <c-q>)
=^
(press a)
=^a
=a
```

Unfortunately, trying to type out our entire payload like before doesn't work. Since `^x` doesn't evaluate to `x`, we can't type `/flag.txt`.

Thankfully, there's a built-in function `glob`, that can autocomplete file paths, so we can just call `glob("/flag.t*t")` to return `"/flag.txt"`.

You might think `glob` won't work either, since `^o` doesn't work, but we can actually just autocomplete `gl` to `glob` with `<c-l>` since it's a built-in function name.

So our final payload, and the flag, looks like this:
```text
=eval(readfile(glob("/flag.t*t"))[0])
E15: Invalid expression: "<left><left><left><left>_c364201e0d86171b"
Press ENTER or type command to continue
E15: Invalid expression: "uiuctf{<left><left><left><left>_c364201e0d86171b}"
Press ENTER or type command to continue
```
vimjail 2.5:
```text
=eval(readfile(glob("/flag.t*t"))[0])
E488: Trailing characters: _kn0w_h0w_7o_ex1t_v1m_7661892ec70e3550
Press ENTER or type command to continue
E15: Invalid expression: "uiuctf{1_kn0w_h0w_7o_ex1t_v1m_7661892ec70e3550}"
Press ENTER or type command to continue
```

# Geoguessr 🧀:warning:🧀:warning:🧀
:warning: This writeup contains a whole bunch of 🧀🧀🧀 :warning:

We're given two files, `janet` and `program.jimage`. Running as instructed, we're faced with a small game that seems impossible:
```text
$ ./janet -i program.jimage
Welcome to geoguesser!
Where am I? 1,1
Nope. You have 4 guesses left.
Where am I? 2,2
Nope. You have 3 guesses left.
Where am I? 3,3
Nope. You have 2 guesses left.
Where am I? 4,4
Nope. You have 1 guesses left.
Where am I? 5,5
You lose!
The answer was: <tuple 0x55BD3C9A5BC0>
```

Now, looking up online, we can see that [janet](https://janet-lang.org/) is a small functional programming language that can compile to `jimage` files. However, in it's compilation process, it actually keeps all strings and function names inside the original source code.

With a small dump we can see:
```text
$ strings program.jimage
root-env
parse-coord
source-map
main.janet
value
parse-coord
main
float
number
some
        peg/match
_000031
_000032,
(parse-coord s)
random-float
random-float
math/rng-uniform
(random-float min max)
main
main
Welcome to geoguesser!
print
init-rng
os/time
math/rng
init-rng,
guessing-game
        get-guess
Where am I?
prin
stdin
line
        file/read
"Not a valid coordinate. Try again.
        get-guess
_000033
input-line
_00003w
num,
compare-coord
compare-float
math/abs
        tolerance
compare-float,
compare-coord
_00003P,
Nope. You have
 guesses left.
answer
guessing-game
guess
        remaining
_00004I,
print-flag
flag.txt
        file/open
You win!
string/trimr
The flag is:
print-flag
        You lose!
The answer was:
(main &)
(init-rng)
*macro-lints*
(compare-float a b tolerance)
(compare-coord a b tolerance)
        precision
(guessing-game answer)
*current-file*
source
coordinate-peg
(get-guess)
(print-flag)
```

A whole lot of nonsense. The main parts of interest are:
```text
init-rng
os/time
math/rng
init-rng
```
and 
```text
random-float
random-float
math/rng-uniform
(random-float min max)
```

Since we know this is a game about guessing coordinates, we can assume it's randomly generating the latitude and longitude. 

But instead of painstakingly reversing this code, let's just reimplement what the original code would have been like.

We can assume based off the first part of interest that `math/rng` gets seeded with `os/time`.

Then, two random floats are generated, calling `math/rng-uniform`, which generates a random number in `[0, 1)`. The `random-float` function also seems to take in a min and a max, so logically, the most reasonable implementation would look like:
```text
random-float = math/rng-uniform # [0, 1)
random-float *= (max - min)
random-float += min
# or in one line
random-float = (math/rng-uniform) * (max - min) + min
```

Now, some quick googling tells us that latitude ranges from -90 to 90, and longitude from -180 to 180.

So all we have to do is just reimplement all this logic ourselves, run our code at the same time we connect to the remote server, and just pass in the same coords.

Here's my reimplementation in `janet` and corresponding solve script:
```text
(def gen (math/rng (os/time)))
(defn random-float [min max]
    (+ min (* (- max min) (math/rng-uniform gen)))
)

(def lat (random-float -90 90))
(def lon (random-float -180 180))
(print lat "," lon)
```
filename=solve.py
```python
import subprocess

test = subprocess.check_output(['./janet', 'test.janet'])
out = test.strip()

from pwn import remote
# nc geoguesser.chal.uiuc.tf 1337
r = remote('geoguesser.chal.uiuc.tf', 1337)
r.sendline(out)
r.interactive()
```

After a few tries and praying we get the timing right, we can get the flag.
```text
[+] Opening connection to geoguesser.chal.uiuc.tf on port 1337: Done
[*] Switching to interactive mode
== proof-of-work: disabled ==
Welcome to geoguesser!
Where am I? You win!
The flag is: uiuctf{i_se3_y0uv3_f0und_7h3_t1m3_t0_r3v_th15_b333b674c1365966}
[*] Got EOF while reading in interactive
$
[*] Interrupted
[*] Closed connection to geoguesser.chal.uiuc.tf port 1337
```

# Pwnykey
The source is pretty small, basically just a simple web-server, so let's take a look at `app.py`:

filename=app.py
```python
#!/usr/bin/env python3
from flask import Flask, request
import threading
import subprocess
import re

app = Flask(__name__)
FLAG = open('flag.txt').read()
lock = threading.Lock()

@app.route('/')
def index():
    return app.send_static_file('index.html')

key_to_check = "00000-00000-00000-00000-00000"
key_format = re.compile(r'^[0-9A-Z]{5}-[0-9A-Z]{5}-[0-9A-Z]{5}-[0-9A-Z]{5}-[0-9A-Z]{5}$')
@app.route('/check', methods=['GET', 'POST'])
def check():
    global key_to_check
    if request.method == 'GET':
        if request.remote_addr != '127.0.0.1':
            return "Forbidden", 403
        try:
            lock.release()
        except:
            pass
        return key_to_check
    else:
        key = request.form['key']
        if not key_format.match(key):
            return "Invalid key format", 400
        lock.acquire()
        key_to_check = key
        process = subprocess.Popen(['./node_modules/@devicescript/cli/devicescript', 'run', '-t', 'keychecker.devs'], stdout=subprocess.PIPE)
        for line in iter(process.stdout.readline, b''):
            if b"success!" in line:
                process.terminate()
                return FLAG
        process.wait()
        return "Incorrect key", 400
```

Nothing too out of the ordinary, except that the `/check` POST endpoint seems to spawn a keychecker using something called `devicescript`.

A quick Google search shows that [`devicescript`](https://github.com/microsoft/devicescript) is a way for IoT devices to run native TypeScript, but more importantly, we also find that it comes with its own [disassembler](https://github.com/microsoft/devicescript/blob/main/compiler/src/disassemble.ts).

Unfortunately, trying to disassemble the `keychecker.devs` as is fails, giving some cryptic error about wrong jump target.

After a bit, my teammate managed to find a pattern (thanks vishi), that could clean up the `keychecker.devs` program and leave it in a state where it was actually disassemblable.

filename=fix_devs.py
```python
def find_all(a_string, sub):
    result = []
    k = 0
    while k < len(a_string):
        k = a_string.find(sub, k)
        if k == -1:
            return result
        else:
            result.append(k)
            #k += 1 #change to k += len(sub) to not search overlapping results
            k += len(sub)
    return result


data = open("keychecker.devs", "rb").read()
NEEDLE = bytes.fromhex("0df90007")

# find all intstances of needle
idxs = find_all(data, NEEDLE)
data_l = list(data)
for idx in idxs:
    data_l[idx + 6] = 0

open("keychecker_fixed.devs", "wb").write(bytes(data_l))
```

Now we can actually disassemble the program and figure out how to make a valid key.

## Disassembled
The full disassembly is a bit long, so I'll leave it as an unlisted pastebin [here](https://pastebin.com/qrAw4CQd). The points of interest will be shown in the writeup, with a bit of cleaning.

Anyway, starting out the disassembly is the main function:
```
proc main_F0(): @1120
  locals: loc0,loc1,loc2
   0:     CALL prototype_F1()
  10:     CALL ds."format"("start!")
  22:     CALL ds."print"(62, ret_val())
  
  34:     CALL fetch_F2("http://localhost/check")
  46:     CALL ret_val()."text"()
  57:     CALL ret_val()."trim"()
  68:     {G4} := ret_val()
  78:     CALL ds."format"("fetched key: {0}", {G4})
  92:     CALL ds."print"(62, ret_val())
```
 
The first thing it does is print `start!`, then fetches the user-submitted key from `/check`, and prints it out:
 
```
 104:     JMP 143 IF NOT ({G4}."length" !== 29)
 121:     CALL (new Error)("Invalid key")
 134:     THROW ret_val()
 
 143:     CALL {G4}."split"("-")
 157:     {G5} := ret_val()
 167:     JMP 206 IF NOT ({G5}."length" !== 5)
 184:     CALL (new Error)("Invalid key")
 197:     THROW ret_val()
 
 206:     CALL {G5}."some"(inline_F7)
 220:     JMP 254 IF NOT ret_val()
 232:     CALL (new Error)("Invalid key")
 245:     THROW ret_val()
```

Then it checks if the length of the key is 29, and splits it by `-`, and checks if there are exactly 5 split segments, each of length 5.

The `inline_F7` function just checks if each individual segment is length 5:
```
proc inline_F7(par0): @4916
   0:     RETURN (par0."length" !== 5)
```

Next, it checks that each segment passes a check called `inline_F8`:
```
 254:     CALL {G5}."some"(CLOSURE(inline_F8))
 268:     JMP 302 IF NOT ret_val()
 280:     CALL (new Error)("Invalid key")
 293:     THROW ret_val()
 302:     CALL ds."format"("key format ok")
 314:     CALL ds."print"(62, ret_val())
...
proc inline_F8(par0): @4924
   0:     CALL par0."split"("")
  14:     CALL ret_val()."some"(inline_F14)
  27:     RETURN ret_val()
...
proc inline_F14(par0): @5292
   0:     CALL "0123456789ABCDFGHJKLMNPQRSTUWXYZ"."includes"(par0)
  14:     RETURN !ret_val()
```
Following the logic, we see that each splits each segment again into individual letters, then checks to see if the letters are in `0123456789ABCDFGHJKLMNPQRSTUWXYZ`. If any are not, it throws an error.

The next part calls `inline_F9` on each segment, which then calls `inline_F15` on each letter in each segment. `inline_F15` just returns the index of the letter in the previously establish alphabet, so this entire process just maps all the letters to their respective indices:
```
 326:     CALL {G5}."map"(CLOSURE(inline_F9))
...
proc inline_F9(par0): @4956
   0:     CALL par0."split"("")
  14:     CALL ret_val()."map"(inline_F15)
  27:     RETURN ret_val()
...
proc inline_F15(par0): @5312
   0:     CALL "0123456789ABCDFGHJKLMNPQRSTUWXYZ"."indexOf"(par0)
  14:     RETURN ret_val()
  
ex: "ABCDE" -> [10, 11, 12, 13, 14]
```
 
It then stores each segment into its own variable:
```
 340:     loc0 := ret_val()
 350:     {G6} := loc0[0]
 363:     {G7} := loc0[1]
 376:     {G8} := loc0[2]
 389:     {G9} := loc0[3]
 402:     {G10} := loc0[4]
 ```
### Check 1
The next part checks `G6`:
```
 415:     CALL ds."format"("{0}", {G6})
 429:     loc0 := ret_val()
 439:     ALLOC_ARRAY initial_size=5
 448:     loc1 := ret_val()
 458:     loc1[0] := 30
 470:     loc1[1] := 10
 482:     loc1[2] := 21
 494:     loc1[3] := 29
 506:     loc1[4] := 10
 518:     CALL ds."format"("{0}", loc1)
```

It stores `G6` into `loc0`, then creates another array in `loc1`, and stores `[30, 10, 21, 29, 10]` into `loc1`. If `loc0` is not equal to `loc1`, then it prints `invalid key`, but otherwise it prints `passed check1`:
```
 518:     CALL ds."format"("{0}", loc1)
 532:     JMP 569 IF NOT (loc0 !== ret_val())
 
 547:     CALL (new Error)("Invalid key")
 560:     THROW ret_val()
 
 569:     CALL ds."format"("passed check1")
 581:     CALL ds."print"(62, ret_val())
```
So we know the first part of the key is `[30, 10, 21, 29, 10]`, which translates to `YANXA` (remember, each number is a corresponding index in the alphabet)

### Check 2
Then, `G7` and `G8` are checked at the same time:
```
 593:     CALL concat_F10({G7}, {G8})
 607:     {G11} := ret_val()
 
 617:     CALL {G11}."reduce"(inline_F11, 0)
 632:     loc0 := (ret_val() !== 134)
 645:     JMP 687 IF NOT !loc0
 
 659:     CALL {G11}."reduce"(inline_F12, 1)
 674:     loc0 := (ret_val() !== 12534912000)
 687:     JMP 722 IF NOT loc0
 
 700:     CALL (new Error)("Invalid key")
 713:     THROW ret_val()
 722:     CALL ds."format"("passed check2")
 734:     CALL ds."print"(62, ret_val())
```
They are concatenated together into `G11`, then pass two checks, `inline_F11` and `inline_F12`. Since `reduce` is called on `G11`, we know that the two inline functions must be accumulators, and they end up being sum and product respectively:
```
proc inline_F11(par0, par1): @5148
   0:     RETURN (par0 + par1)

proc inline_F12(par0, par1): @5156
   0:     RETURN (par0 * par1)
```
This means that `G11` must contain 10 numbers that add up to `134`, and have a product of `12534912000`. Of course, we can easily just solve this with `z3`:

filename=z3solve.py
```python
import z3
s = z3.Solver()

x = [z3.Int(f"x{i}") for i in range(10)]
# ten numbers add up to 134, multiply to 12534912000
s.add(sum(x) == 134)
s.add(z3.Product(x) == 12534912000)
for i in range(10):
    s.add(x[i] >= 0)
    s.add(x[i] < 32) # only 32 characters in alphabet

s.check()
m = s.model()
print(m)
nums = []
for i in range(10):
    nums.append(m[x[i]].as_long())
print(nums)
# [15, 2, 15, 5, 4, 9, 13, 16, 31, 24]
```
Since the check was done with `reduce`, the order of the numbers don't matter, so we can just translate them directly, giving us the next two sections: `YANXA-G2G54-9DHZR`

### Check 3
The next (and final) part is the most complex. First, `G9` is stored into `G12`, and `G13` is set to `1337`. Then, a loop is run 420 times, each time calling `nextInt_F13`:
```
 746:     {G12} := {G9}
 757:     {G13} := 1337
 
 770:     loc2 := 0
 780:     JMP 832 IF NOT (loc2 < 420)
 798:     CALL nextInt_F13()
 808:     loc2 := (loc2 + 1)
 821:     JMP 780
```
Looking at `nextInt_F13`, we find what seems to be a basic [`xorwow`](https://en.wikipedia.org/wiki/Xorshift#xorwow) PRNG, with `G13` serving as the counter to modify the output:
```
proc nextInt_F13(): @5164
  locals: loc0
   0:     CALL {G12}."pop"()
  12:     loc0 := ret_val()
  
  22:     loc0 := (loc0 ^ ((loc0 >> 2) & 4294967295))
  41:     loc0 := (loc0 ^ ((loc0 << 1) & 4294967295))
  60:     loc0 := (loc0 ^ (({G12}[0] ^ ({G12}[0] << 4)) & 4294967295))
  
  86:     {G13} := (({G13} + 13371337) & 4294967295
 106:     CALL {G12}."unshift"(loc0)
 120:     RETURN (loc0 + {G13})
```
This PRNG pops the last value of `G12`, does `xorshift` operations, then inserts it back into the start of `G12`. Then, at the same time, `G13` is increased by `13371337`, and only added to the final output of the PRNG.

Going back to the main function, after the loop is run, an array is created and initialized with 3 calls to `nextInt_F13`, then compared with another array:
```
 832:     ALLOC_ARRAY initial_size=3
 841:     loc0 := ret_val()
 851:     CALL nextInt_F13()
 861:     loc0[0] := ret_val()
 873:     CALL nextInt_F13()
 883:     loc0[1] := ret_val()
 895:     CALL nextInt_F13()
 905:     loc0[2] := ret_val()
 917:     CALL ds."format"("{0}", loc0)
 931:     loc0 := ret_val()
 
 941:     ALLOC_ARRAY initial_size=3
 950:     loc1 := ret_val()
 960:     loc1[0] := 2897974129
 973:     loc1[1] := -549922559
 990:     loc1[2] := -387684011
1007:     CALL ds."format"("{0}", loc1)

1021:     JMP 1058 IF NOT (loc0 !== ret_val())
1036:     CALL (new Error)("Invalid key")
1049:     THROW ret_val()

1058:     CALL ds."format"("passed check3")
1070:     CALL ds."print"(62, ret_val())
```

This means to pass this check, we need to somehow initialize `G12` with the proper state so that after 420 `nextInt` calls, we generate the exact integers `[2897974129, -549922559, -387684011]`. 

Before we start trying to solve this, another thing to realize is that `G13`, the counter, can be solved seperately from the rest of the `xorwow` PRNG. Since we know the amount of times
the PRNG is called, we can pre-calculate the value `G13` when it will be called the last 3 times, and just subtract them from the target values:

filename=calc_g13.py
```python
import ctypes
target = [2897974129, -549922559, -387684011]
g13 = 1337
for _ in range(420):
    g13 = ctypes.c_int32(g13 + 13371337).value

for i in range(3):
    g13 = ctypes.c_int32(g13 + 13371337).value
    target[i] -= g13

print(target)
# [1563607211, -1897660814, -1748793603]
```

As for solving the actual xorshift part, after a bit of mucking around with Z3 and reversing, we realized that brute force was actually feasible. This is because there are only 5 numbers in the state, and each number can only have an initial value in 0-31, since there are only 32 letters in the alphabet.

That leaves a total search space of `2^(5*5) = 33554432` which is definitely small enough to brute force.

I ended up coding my brute force in c++, directly translating the logic over: 

filename=brute.cpp
```c++
#include <iostream>
#include <string>
#include <vector>

using namespace std;

vector<int> state(5);

int nextInt(){
    int last = state.back();
    state.pop_back();
    
    int nxt = last ^ (last >> 2);
    nxt = nxt ^ (nxt << 1);
    nxt = nxt ^ (state[0] ^ (state[0] << 4));
    state.insert(state.begin(), nxt);
    return nxt;
}

int main(){
    // start
    cout << time(0) << endl;
    for(int a = 0; a < 32; a++){
    for(int b = 0; b < 32; b++){
    for(int c = 0; c < 32; c++){
    for(int d = 0; d < 32; d++){
    for(int e = 0; e < 32; e++){
        state = {a, b, c, d, e};
        for(int i = 0; i < 420; i++){
            nextInt();
        }
        // 1563607211, -1897660814, -1748793603
        int tmp = nextInt();
        if(tmp == 1563607211){
            tmp = nextInt();
            if(tmp == -1897660814){
                tmp = nextInt();
                if (tmp == -1748793603){
                    cout << "found! " << a << " " << b << " " << c << " " << d << " " << e << endl;
                    cout << time(0) << endl;
                    return 0;
                }
            }
        }
    }
    }
    }
    }
    }
    cout << time(0) << endl;
    return 1;
}
```

Even though the code is kinda ugly and unoptimized, compiling with `-O3` and letting it run only took ~60 seconds to finish and spit out a valid answer:
```
$ g++ -o brute -O3 'brute.cpp'
$ ./brute
1688339552
found! 14 11 22 2 27
1688339618
```

### Finale
Now our key is looking like `YANXA-G2G54-9DHZR-FBP2U`. But what about the last part? Well going back to the disassembly, we see that after passing the 3rd check, the last segment isn't used at all. Instead, after passing check 3, the program just prints `success!` and exits:
```
1058:     CALL ds."format"("passed check3")
1070:     CALL ds."print"(62, ret_val())
1082:     CALL ds."format"("success!")
1094:     CALL ds."print"(62, ret_val())
1106:     RETURN 0
```

This means we can do anything for the last 5 digits, so of course, our key is now: 
```YANXA-G2G54-9DHZR-FBP2U-XDUWU```

Passing this to the website, we're finally *finally* able to get our proper PwnyOS license! Oh, and the flag too
```
uiuctf{abbe62185750af9c2e19e2f2}
```

# Schrödinger's Cat
Finally, we're at the last challenge. This one is a bit different from the rest, and involves constructing a quantum circuit to solve a problem. Don't worry though, this writeup assumes no prior knowledge of quantum computing, and will explain everything you need to know.

First, let's take a look at the provided file:

filename=server.py
```python
#!/usr/bin/env python3

from os import system
from base64 import b64decode
import numpy as np

from qiskit import QuantumCircuit
import qiskit.quantum_info as qi
from qiskit.circuit.library import StatePreparation

WIRES = 5


def normalization(msg):
    assert(len(msg) <= WIRES**2)
    state = np.array([ord(c) for c in msg.ljust(2**WIRES, ' ')])
    norm = np.linalg.norm(state)
    state = state / norm
    return (state, norm)

def transform(sv, n):
    legal = lambda c: ord(' ') <= c and c <= ord('~')
    renormalized = [float(i.real)*n for i in sv]
    rn_rounded = [round(i) for i in renormalized]
    if not np.allclose(renormalized, rn_rounded, rtol=0, atol=1e-2):
        print("Your rehydrated statevector isn't very precise. Try adding at least 6 decimal places of precision, or contact the challenge author if you think this is a mistake.")
        print(rn_rounded)
        exit(0)
    if np.any([not legal(c) for c in rn_rounded]):
        print("Invalid ASCII characters.")
        exit(0)
    return ''.join([chr(n) for n in rn_rounded])

def make_circ(sv, circ):
    qc = QuantumCircuit(WIRES)
    qc.append(circ.to_instruction(), range(WIRES))
    sp = QuantumCircuit(WIRES, name="echo 'Hello, world!'")
    sp.append(StatePreparation(sv), range(WIRES))
    qc.append(sp.to_instruction(), range(WIRES))
    return qc

def print_given(sv, n):
    placeholder = QuantumCircuit(WIRES, name="Your Circ Here")
    placeholder.i(0)

    circ = make_circ(sv, placeholder)
    print(circ.draw(style={
        "displaytext": {
            "state_preparation": "<>"
            }
        }))
    new_sv = qi.Statevector.from_instruction(circ)
    print(f'Normalization constant: {n}')
    print("\nExecuting...\n")
    system(transform(new_sv, n))

def main():
    print("Welcome to the Quantum Secure Shell. Instead of dealing with pesky encryption, just embed your commands into our quantum computer! I batched the next command in with yours, hope you're ok with that!")

    given_sv, given_n = normalization("echo 'Hello, world!'")
    print_given(given_sv, given_n)

    try:
        qasm_str = b64decode(input("\nPlease type your OpenQASM circuit as a base64 encoded string: ")).decode()
    except:
        print("Error decoding b64!")
        exit(0)
    try:
        circ = QuantumCircuit.from_qasm_str(qasm_str)
        circ.remove_final_measurements(inplace=True)
    except:
        print("Error processing OpenQASM file! Try decomposing your circuit into basis gates using `transpile`.")
        exit(0)
    if circ.num_qubits != WIRES:
        print(f"Your quantum circuit acts on {circ.num_qubits} instead of {WIRES} qubits!")
        exit(0)

    try:
        norm = float(input("Please enter your normalization constant (precision matters!): "))
    except:
        print("Error processing normalization constant!")
        exit(0)
    try:
        sv_circ = make_circ(given_sv, circ)
    except:
        print("Circuit runtime error!")
        exit(0)

    print(sv_circ.draw())
    command = transform(qi.Statevector.from_instruction(sv_circ), norm)

    print("\nExecuting...\n")
    system(command)

if __name__ == "__main__":
    main()
```

It might look like a lot, so I'll break it down step by step.

First, the server prints a welcome message, then executes its built-in quantum circuit and prints out its result:
```python
def main():
    print("Welcome to the Quantum Secure Shell. Instead of dealing with pesky encryption, just embed your commands into our quantum computer! I batched the next command in with yours, hope you're ok with that!")

    given_sv, given_n = normalization("echo 'Hello, world!'")
    print_given(given_sv, given_n)
```
The specific implemenetation of `normalization` and `print_given` aren't important yet, but just know that `normalization` returns a statevector and a normalization constant and `print_given` is just an extension of the welcome message.

A [statevector](https://en.wikipedia.org/wiki/Quantum_state) is way to represent the possible states of a quantum system, and records the probabilities of every possible combination of qubit measurements. For example, the statevector of a single qubit at the start of a circuit is `[1, 0]`, since it will always record 0 when measured. A statevector that records `n` qubits requires `2^n` values.

A key property of statevectors is that the sum of the squares of all values in the statevector must equal 1. This is called normalization, and the normalization constant is what the statevector is divided by to ensure it is normalized. 

In this case, the statevector is 32 values long, and represents the 5 qubits used in the circuit. In the output of `print_given`, we can also see that the normalization constant is `419.1873089681986`.

