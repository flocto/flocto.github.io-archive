---
title: "Updates and Teaser"
date: 2023-11-17T10:32:48-06:00
summary: "A long awaited update and announcements, as well as a small teaser for an upcoming blog post."
tags: ["2023", "updates"]
---

It's been quite a while since I've posted here, I hope everyone is doing well.

Been busy with school ever since it started, so I haven't had much time to make decent writeups. Thankfully,
with exams on the horizon, I'll finally have time to write some posts.

Anyway, first things first, I think I'll be moving away from Hugo in the upcoming months. I've been looking at [eleventy](https://www.11ty.dev/) recently and it looks pretty promising. Hopefully the shift doesn't break too many of my old posts, but if they do just know I won't be fixing them. ~~cuz im lazy~~

In terms of cybersecurity, I finally got a job! Hooray. Still looking for something for the summer but at least I get some working experience.

As for CTFs, I've been doing them like normal. Unfortunately I'll probably never be able to go back and make writeups for most of them, but some fun ones I did recently include UDCTF, LakeCTF Quals, and HITCON. 

At HITCON, we managed to qualify for the finals and got 2nd place! Really fun CTF even if I didn't mess with too much of the A/D side (was farming koth xd).

I also qualified and went to CSAW Finals, but unfortunately I spent my entire time tunnel-visioned on one challenge so I didn't do too well. Still pretty fun, and the food in NYC was great. (Unfortunately I did lose my phone on the way back, but that's a story for another time.)

With those updates out of the way, let's get to the teaser.

## Teaser
In the upcoming months with the transition to eleventy, I also plan on making a series of blog posts where I dive into different programming languages and discuss their features, mainly discussing how I would approach reversing them for CTFs.
Note that my advice may not be the best, but this is mainly more for me to force myself to learn these languages rather than as an actual guide.

As a teaser for the first post, if you played in HITCON Finals recently, you may recall the KOTH challenge `expansion`, where you were given 5 different "binaries" all compiled with ELVM. I'll be going over one of the esolangs from that challenge, Befunge, so as a gift here's a basic (and possibly slightly broken) interpreter that I've written.

filename=befunge.py
```python
from random import randint
import os.path
import sys

class BefungeGrid:
    grid = {}
    def __init__(self):
        self.grid = {}
        self.row_bound = 0
        self.col_bound = 0

    def __getitem__(self, key):
        if type(key) == tuple:
            # parse as row, col
            return self.grid.get(key[0], {}).get(key[1], " ")
        
        return self.grid.get(key, {}) # ? may be incomplete row, due to being sparse
    
    def __setitem__(self, key, value):
        if type(key) == tuple:
            # parse as row, col
            self.grid.setdefault(key[0], {})[key[1]] = value
        else:
            self.grid[key] = value
    
    def read_file(self, filename):
        data = open(filename).readlines()
        self.col_bound = len(data)
        for row, line in enumerate(data):
            line = line.strip('\n') # remove trailing newline
            self.row_bound = max(self.row_bound, len(line))
            for col, char in enumerate(line):
                if char != ' ':
                    self.grid.setdefault(row, {})[col] = char

    # for bounds, we assume only the original grid matters
    # THIS IS IMPT IF YOU OVERWRITE AN AREA NEAR THE EDGE
    def get_row_bound(self):
        return self.row_bound
    
    def get_col_bound(self):
        return self.col_bound

# GLOBAL VARIABLES
grid = BefungeGrid() # BEFUNGE GRID 
x = 0                # X COORDINATE OF POINTER
y = 0                # Y COORDINATE OF POINTER
direction = 0        # CURRENT DIRECTION OF MOTION
stack = []           # STACK OF POINTER
inQuotes = False     # WHETHER WE'RE IN STRING MODE
globalPC = 0         # GLOBAL PROGRAM COUNTER

def main():
    global globalPC
    if len(sys.argv) < 2:
        print("ERROR: No input file specified!")
        sys.exit()

    filename = sys.argv[1]
    if not os.path.isfile(filename):
        print("ERROR: Specified input file does not exist!")
        sys.exit()

    grid.read_file(filename)
    # printGrid(grid)
    
    while grid[y, x] != "@":
        globalPC += 1
        step()
    
def printGrid(grid: BefungeGrid, MAX_X=100, MAX_Y=100):
    """Print the grid to the console"""
    for row in range(MAX_Y):
        for col in range(grid.get_row_bound()):
            print(grid[row, col], end="")
        print()

def step():
    # print(f"{globalPC} ({y}, {x}) {grid[y, x]}")
    processInstruction(grid[y, x])
    move()

def processInstruction(inst: str):
    global direction, inQuotes

    # IN STRING MODE
    if inQuotes and inst != '"':
        stack.append(ord(inst))
        return
    
    # NOP
    if inst == " ":
        return
    
    # TOGGLE STRING MODE
    elif inst == '"':
        inQuotes = not inQuotes
    
    # MOVEMENT
    elif inst in '>v<^':
        direction = '>v<^'.index(inst)

    elif inst == '#': # skip
        move()

    # LITERAL
    elif inst.isdigit():
        stack.append(int(inst))

    # ARITHMETIC
    elif inst in '+-*%':
        a, b = stack.pop(), stack.pop()
        stack.append(eval(f'{b}{inst}{a}'))
    elif inst == '/': # special case
        a, b = stack.pop(), stack.pop()
        stack.append(b // a)
    
    # BOOLEAN
    elif inst == '!': # logical not
        stack.append(not stack.pop())
    
    elif inst == '`': # greater than
        a, b = stack.pop(), stack.pop()
        stack.append(int(b > a))

    # RANDOM
    elif inst == '?': # random direction
        direction = randint(0, 3)
    
    # CONDITIONALS
    elif inst == '_': # horizontal if
        if not stack.pop():
            direction = 0
        else:
            direction = 2

    elif inst == '|':
        if not stack.pop():
            direction = 1
        else:
            direction = 3

    # STACK OPS
    elif inst == ':': # dup
        stack.append(stack[-1])
    
    elif inst == '\\': # swap
        a, b = stack.pop(), stack.pop()
        stack.append(a)
        stack.append(b)
    
    elif inst == '$': # pop
        stack.pop()
    
    # OUTPUT
    elif inst == '.': # output int
        print(stack.pop(), end=" ")
    
    elif inst == ',': # output char
        print(chr(stack.pop()), end="")
    
    # MODIFY
    # THESE HAVE SPECIAL BEHAVIOR WHEN DATA IS NOT ASCII
    elif inst == 'p': # put
        y, x, v = stack.pop(), stack.pop(), stack.pop()
        if 32 <= v <= 126:
            grid[y, x] = chr(v)
        else:
            grid[y, x] = v
    
    elif inst == 'g': # get
        y, x = stack.pop(), stack.pop()
        v = grid[y, x]
        if type(v) == str:
            stack.append(ord(v))
        else:
            stack.append(v)

    # INPUT
    elif inst == '&': # input int
        stack.append(int(input("(n) > ")))
    
    elif inst == '~': # input char
        stack.append(ord(input("(c) > ")))


def move():
    global x, y
    # right, down, left, up
    dxy = [(0, 1), (1, 0), (0, -1), (-1, 0)]
    dy, dx = dxy[direction]
    x += dx
    y += dy
    
    # WRAP AROUND IF NECESSARY
    x %= grid.get_row_bound() 
    y %= grid.get_col_bound()

    

if __name__ == "__main__":
    main()
```

And of course, I can't end the teaser without a challenge. Here's a small Befunge program that I wrote, can you figure out what it does?

filename=challenge.bef
```text
      >92+2*1+3*99*99*v
v  *99               p<
&                      
\                      
     >:00p -,  v       
     \                 
  >\:|:\ +1 g00<       
  -  @                 
  3                    
  0                    
  ^"Vmt ekg$nz("0<     
                 |    <
          @,,"NO"<     
>99*g 55+::**67**+  -!^
```

That's all for now, see you soon!