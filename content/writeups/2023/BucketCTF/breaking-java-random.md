---
title: "Breaking Java Random - BucketCTF 2023 Writeup"
date: 2023-04-12T23:08:49-05:00
tags: ["rev", "bucketctf", "2023"]
summary: Cracking Java's util.Random RNG with only 1 sample.
mathjax: true
---

The promised reverse engineering writeup is finally here. This post will feature 3 challenges: `random security`, `maze`, and `image`. 
While `image` is categorized as `crypto`, I feel like that's a gross misrepresentation of the challenge, so I'm putting all 3 as rev.

Let's start out with the most basic challenge: `random security`. 
## Random Security - 452 - Medium
> One of my *friends* recently learned **Java** and started teasing all of us for not knowing anything about programming. He made what he called a *secure* program and challenged us to steal some flag from it. I have no idea where to even start, could you help out?

We're not given any source, so let's just connect to the server and see what we get.

```terminal
$ nc 213.133.103.186 32811
Since I am nice I will give you a random number:
0.1406976754934386
Now give me one!
123
WRONG DOUBLE!!!!!
```

Seems like we have to generate another random number and send it back. Given the flavortext of the challenge and the server messages, we probably have the generate the result of the `nextDouble` method of the `Random` class. 

The server seems to be giving us a single output of `nextDouble` as well, so somehow we need to recover the random seed from that, and then generate the next double for the server.

Let's take a look at the relevant source code for `Random`:

```java
public class Random {
    private final AtomicLong seed;
    private static final long multiplier = 0x5DEECE66DL;
    private static final long addend = 0xBL;
    private static final long mask = (1L << 48) - 1;
    /* ... */
    protected int next(int bits) {
        long oldseed, nextseed;
        AtomicLong seed = this.seed;
        do {
            oldseed = seed.get();
            nextseed = (oldseed * multiplier + addend) & mask;
        } while (!seed.compareAndSet(oldseed, nextseed));
        return (int)(nextseed >>> (48 - bits));
    }
    /* ... */
    private static final double DOUBLE_UNIT = 0x1.0p-53; // 1.0 / (1L << 53)
    public double nextDouble() {
        return (((long)(next(26)) << 27) + next(27)) * DOUBLE_UNIT;
    }
}
```

The `next` method is the core of the RNG, and it's pretty simple. It's just a linear congruential generator (LCG) with a 48-bit modulus. 
The values of `multiplier`, `addend`, and `mask` are all constants, so we can just hardcode them if needed.

To generate a double like the server is doing, there are 2 calls being made to `next`. This means that we are able to extract the top 26 bits from the first `next` call, and the top 27 bits from the second `next` call. 

```python
double = 0.1406976754934386

state = double * (1 << 53)
state = int(state)
print(state)

first26 = state >> 27
second27 = state & ((1 << 27) - 1)

print(bin(first26)[2:].zfill(26), bin(second27)[2:].zfill(27))
# 1267291997848290
# 00100100000001001100001101 001010110111100001011100010
```

However, this still isn't enough to completely predict all the outputs. We still don't know the full value of `seed`.

Thankfully, because we're given the top `26` bits of the state before the second `next` call, we can easily brute force the remaining `48 - 26 = 22` bits.
To verify, `2 ^ 22 = 4194304`, which is tiny in terms of brute forcing.

To save time, I just directly ported over the algorithm listed [here](https://franklinta.com/2014/08/31/predicting-the-next-math-random-in-java/) into Python, and it worked perfectly.

```python
double = 0.1406976754934386

state = double * (1 << 53)
state = int(state)
print(state)

first26 = state >> 27
second27 = state & ((1 << 27) - 1)
print(bin(first26)[2:].zfill(26), bin(second27)[2:].zfill(27))

multiplier = 0x5DEECE66D
addend = 0xB

mask = ((1<<27)-1) << (48 - 27)
oldseedupper26 = first26 << (48 - 26) & mask
newseedupper27 = second27 << (48 - 27) & mask
possibleSeeds = []

from tqdm import tqdm
for oldseed in tqdm(range(oldseedupper26, oldseedupper26 + ((1 << (48 - 26))))):
    newseed = oldseed * multiplier + addend
    newseed = newseed & ((1 << 48) - 1)
    if newseed & mask == newseedupper27:
        possibleSeeds.append(oldseed)

print(possibleSeeds)
if len(possibleSeeds) != 1:
    print('Error')
    exit(1)

seed = possibleSeeds[0]
# seed = 39602878128263
```

Now all we have to do is reimplement the `next` and `nextDouble` methods.

```python
def next(bits):
    global seed
    seed = (seed * multiplier + addend) & ((1 << 48) - 1)
    return seed >> (48 - bits)

def nextDouble():
    return ((next(26) << 27) + next(27)) / (1 << 53)
```

Finally, we can send the next generated double back to the server and finally get the flag. Before we generate the next double though, we do have to make
a single `next` call, as the seed we recovered is the seed after the first `next` call in the `nextDouble` method, so we still need to go through the second one.

Here's the full script:
```python
from pwn import remote
from tqdm import tqdm

r = remote('213.133.103.186', 32815, level='error')
r.recvline()
double = float(r.recvline().decode().strip())
print(double)

state = double * (1 << 53)
state = int(state)
print(state)

first26 = state >> 27
second27 = state & ((1 << 27) - 1)
print(bin(first26)[2:].zfill(26), bin(second27)[2:].zfill(27))

multiplier = 0x5DEECE66D
addend = 0xB

mask = ((1<<27)-1) << (48 - 27)
oldseedupper26 = first26 << (48 - 26) & mask
newseedupper27 = second27 << (48 - 27) & mask
possibleSeeds = []

from tqdm import tqdm
for oldseed in tqdm(range(oldseedupper26, oldseedupper26 + ((1 << (48 - 26))))):
    newseed = oldseed * multiplier + addend
    newseed = newseed & ((1 << 48) - 1)
    if newseed & mask == newseedupper27:
        possibleSeeds.append(oldseed)

print(possibleSeeds)
if len(possibleSeeds) != 1:
    print('Error')
    exit(1)

seed = possibleSeeds[0]

def next(bits):
    global seed
    seed = (seed * multiplier + addend) & ((1 << 48) - 1)
    return seed >> (48 - bits)

def nextDouble():
    return ((next(26) << 27) + next(27)) / (1 << 53)

next(1)
nxtd = nextDouble()
r.sendline(str(nxtd).encode())
r.recvline()
print(r.recvline().decode().strip())
```
After running for just a few seconds, we get our flag:
```
0.19317240683223058
1739942358855791
00110001011100111011111100 110001110101011000001101111
100%|████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 4194304/4194304 [00:03<00:00, 1110484.95it/s] 
[54373198860349]
Correct! Here is your flag: bucket{RaNd0m_nUmb3r5_53cur3_d24d8c961}
```

Now let's see how we can take this a step further with our next challenge, `maze`.

## Maze - 478 - Hard
> After you solved my last challenge I have upped my game. This time there is no way you will find the flag. Im so confident you will lose that I will give you the file to the game. Good luck! You're gonna need it.
> 
> [https://storage.ebucket.dev/Maze.class](https://storage.ebucket.dev/Maze.class)

This time we're given a `.class` file, so let's decompile it [here](http://www.javadecompilers.com/) again to get the source code.
Thankfully, it's not obfuscated like [Troll](https://flocto.github.io/writeups/2023/bucketctf/bucketctf-megathread/#troll---464---hard) was, so we can actually read it.

```java
import java.io.FileNotFoundException;
import java.util.Scanner;
import java.io.File;
import java.util.Random;

public class Maze
{
    public static char[][] maze;
    public static Random random = new Random();
    
    public static String getFlag() {
        try {
            return new Scanner(new File("flag.txt")).nextLine();
        }
        catch (FileNotFoundException ex) {
            System.out.println("There has been an unexpected error. Please report this to the CTF admins.");
            return "";
        }
    }
    
    public static void initMap() {
        System.out.println("I've learned from my mistakes and this time I will construct a full maze you will never be able to break out of!!!");
        maze = new char[41][41];
        for (int i = 1; i <= 20; ++i) {
            if (i % 2 == 1) {
                for (int j = 20 - i; j <= 20 + i; ++j) {
                    for (int k = 20 - i; k <= 20 + i; ++k) {
                        if (j == 20 - i || j == 20 + i || k == 20 - i || k == 20 + i) {
                            maze[j][k] = '#';
                        }
                    }
                }
            }
        }
        for (int l = 0; l < maze.length; ++l) {
            for (int n = 0; n < maze[l].length; ++n) {
                if (maze[l][n] != '#') {
                    maze[l][n] = ' ';
                }
                System.out.print(maze[l][n]);
            }
            System.out.println();
        }
        for (int n2 = 0; n2 < 10; ++n2) {
            final int bound = 3 + n2 * 4;
            final int nextInt = random.nextInt(bound);
            switch (random.nextInt(4)) {
                case 0: {
                    maze[20 + bound / 2][20 - bound / 2 + nextInt] = ' ';
                    break;
                }
                case 1: {
                    maze[20 - bound / 2 + nextInt][20 + bound / 2] = ' ';
                    break;
                }
                case 2: {
                    maze[20 - bound / 2][20 - bound / 2 + nextInt] = ' ';
                    break;
                }
                case 3: {
                    maze[20 - bound / 2 + nextInt][20 - bound / 2] = ' ';
                    break;
                }
            }
        }
        maze[20][20] = 'X';
    }
    
    public static void main(final String[] array) {
        initMap();
        int n = 20;
        int n2 = 20;
        try {
            final Scanner scanner = new Scanner(System.in);
            while (true) {
                final char char1 = scanner.next().charAt(0);
                if (char1 == 'Q') {
                    if (maze[n - 1][n2 - 1] == '#') {
                        break;
                    }
                    maze[n][n2] = ' ';
                    maze[--n][--n2] = 'X';
                }
                if (char1 == 'W') {
                    if (maze[n - 1][n2] == '#') {
                        break;
                    }
                    maze[n][n2] = ' ';
                    maze[--n][n2] = 'X';
                }
                if (char1 == 'E') {
                    if (maze[n - 1][n2 + 1] == '#') {
                        break;
                    }
                    maze[n][n2] = ' ';
                    maze[--n][++n2] = 'X';
                }
                if (char1 == 'D') {
                    if (maze[n][n2 + 1] == '#') {
                        break;
                    }
                    maze[n][n2] = ' ';
                    maze[n][++n2] = 'X';
                }
                if (char1 == 'C') {
                    if (maze[n + 1][n2 + 1] == '#') {
                        break;
                    }
                    maze[n][n2] = ' ';
                    maze[++n][++n2] = 'X';
                }
                if (char1 == 'S') {
                    if (maze[n + 1][n2] == '#') {
                        break;
                    }
                    maze[n][n2] = ' ';
                    maze[++n][n2] = 'X';
                }
                if (char1 == 'Z') {
                    if (maze[n + 1][n2 - 1] == '#') {
                        break;
                    }
                    maze[n][n2] = ' ';
                    maze[++n][--n2] = 'X';
                }
                if (char1 == 'A') {
                    if (maze[n][n2 - 1] == '#') {
                        break;
                    }
                    maze[n][n2] = ' ';
                    maze[n][--n2] = 'X';
                }
                if (char1 == 'R') {
                    System.out.println("Here is a random number for you since i'm nice: " + random.nextDouble());
                }
            }
            scanner.close();
            System.out.println("YOU LOSE I WIN! BETTER LUCK NEXT TIME!");
        }
        catch (Exception ex) {
            if (ex instanceof ArrayIndexOutOfBoundsException) {
                System.out.println(getFlag());
            }
        }
    }
}
```

It's a bit long, so let's start decomposing it. Let's start from our goal, the `getFlag` function.

```java
public static String getFlag() {
    try {
        return new Scanner(new File("flag.txt")).nextLine();
    }
    catch (FileNotFoundException ex) {
        System.out.println("There has been an unexpected error. Please report this to the CTF admins.");
        return "";
    }
}
```
The only place this is called is at the end of the main method:
```java
catch (Exception ex) {
    if (ex instanceof ArrayIndexOutOfBoundsException) {
        System.out.println(getFlag());
    }
}
```
Which means to get the flag, we somehow need to throw an `ArrayIndexOutOfBoundsException`.

Looking at the rest of the main method, we can clearly see the intended way to do this: We just need to somehow escape out of maze and reach the border.

```java
try {
    final Scanner scanner = new Scanner(System.in);
    while (true) {
        final char char1 = scanner.next().charAt(0);
        if (char1 == 'Q') {
            if (maze[n - 1][n2 - 1] == '#') {
                break;
            }
            maze[n][n2] = ' ';
            maze[--n][--n2] = 'X';
        }
        if (char1 == 'W') {
            if (maze[n - 1][n2] == '#') {
                break;
            }
            maze[n][n2] = ' ';
            maze[--n][n2] = 'X';
        }
        if (char1 == 'E') {
            if (maze[n - 1][n2 + 1] == '#') {
                break;
            }
            maze[n][n2] = ' ';
            maze[--n][++n2] = 'X';
        }
        if (char1 == 'D') {
            if (maze[n][n2 + 1] == '#') {
                break;
            }
            maze[n][n2] = ' ';
            maze[n][++n2] = 'X';
        }
        if (char1 == 'C') {
            if (maze[n + 1][n2 + 1] == '#') {
                break;
            }
            maze[n][n2] = ' ';
            maze[++n][++n2] = 'X';
        }
        if (char1 == 'S') {
            if (maze[n + 1][n2] == '#') {
                break;
            }
            maze[n][n2] = ' ';
            maze[++n][n2] = 'X';
        }
        if (char1 == 'Z') {
            if (maze[n + 1][n2 - 1] == '#') {
                break;
            }
            maze[n][n2] = ' ';
            maze[++n][--n2] = 'X';
        }
        if (char1 == 'A') {
            if (maze[n][n2 - 1] == '#') {
                break;
            }
            maze[n][n2] = ' ';
            maze[n][--n2] = 'X';
        }
        if (char1 == 'R') {
            System.out.println("Here is a random number for you since i'm nice: " + random.nextDouble());
        }
    }
    scanner.close();
    System.out.println("YOU LOSE I WIN! BETTER LUCK NEXT TIME!");
}
```

This while true loop implements a basic movement system that looks like this:
```
QWE
A D
ZSC
```
Where `Q` moves up and to the left, `W` just moves up, and so on. If we ever move onto a `#`, the loop ends and the program exits. This means we have to somehow escape the maze without ever touching a `#`.

We also have a special input, `R`, that gives us a randomly generated double. *Hmm, I wonder how this could help us...*

Let's look at the final part of the code, `initMap`:
```java
public static void initMap() {
    System.out.println("I've learned from my mistakes and this time I will construct a full maze you will never be able to break out of!!!");
    maze = new char[41][41];
    for (int i = 1; i <= 20; ++i) {
        if (i % 2 == 1) {
            for (int j = 20 - i; j <= 20 + i; ++j) {
                for (int k = 20 - i; k <= 20 + i; ++k) {
                    if (j == 20 - i || j == 20 + i || k == 20 - i || k == 20 + i) {
                        maze[j][k] = '#';
                    }
                }
            }
        }
    }
    for (int l = 0; l < maze.length; ++l) {
        for (int n = 0; n < maze[l].length; ++n) {
            if (maze[l][n] != '#') {
                maze[l][n] = ' ';
            }
            System.out.print(maze[l][n]);
        }
        System.out.println();
    }
    for (int n2 = 0; n2 < 10; ++n2) {
        final int bound = 3 + n2 * 4;
        final int nextInt = random.nextInt(bound);
        switch (random.nextInt(4)) {
            case 0: {
                maze[20 + bound / 2][20 - bound / 2 + nextInt] = ' ';
                break;
            }
            case 1: {
                maze[20 - bound / 2 + nextInt][20 + bound / 2] = ' ';
                break;
            }
            case 2: {
                maze[20 - bound / 2][20 - bound / 2 + nextInt] = ' ';
                break;
            }
            case 3: {
                maze[20 - bound / 2 + nextInt][20 - bound / 2] = ' ';
                break;
            }
        }
    }
    maze[20][20] = 'X';
}
```

First, we have the actual maze generation:
```java
maze = new char[41][41];
for (int i = 1; i <= 20; ++i) {
    if (i % 2 == 1) {
        for (int j = 20 - i; j <= 20 + i; ++j) {
            for (int k = 20 - i; k <= 20 + i; ++k) {
                if (j == 20 - i || j == 20 + i || k == 20 - i || k == 20 + i) {
                    maze[j][k] = '#';
                }
            }
        }
    }
}
```

Then, the maze gets printed out. This should be the first thing we see when we connect to the server, so let's do that as well as see what we get.

```java
for (int l = 0; l < maze.length; ++l) {
    for (int n = 0; n < maze[l].length; ++n) {
        if (maze[l][n] != '#') {
            maze[l][n] = ' ';
        }
        System.out.print(maze[l][n]);
    }
    System.out.println();
}
```
```terminal
$ 213.133.103.186 31851
I've learned from my mistakes and this time I will construct a full maze you will never be able to break out of!!!
                                         
 ####################################### 
 #                                     # 
 # ################################### # 
 # #                                 # # 
 # # ############################### # # 
 # # #                             # # # 
 # # # ########################### # # # 
 # # # #                         # # # # 
 # # # # ####################### # # # # 
 # # # # #                     # # # # # 
 # # # # # ################### # # # # # 
 # # # # # #                 # # # # # # 
 # # # # # # ############### # # # # # # 
 # # # # # # #             # # # # # # # 
 # # # # # # # ########### # # # # # # # 
 # # # # # # # #         # # # # # # # # 
 # # # # # # # # ####### # # # # # # # # 
 # # # # # # # # #     # # # # # # # # # 
 # # # # # # # # # ### # # # # # # # # # 
 # # # # # # # # # # # # # # # # # # # # 
 # # # # # # # # # ### # # # # # # # # # 
 # # # # # # # # #     # # # # # # # # # 
 # # # # # # # # ####### # # # # # # # # 
 # # # # # # # #         # # # # # # # # 
 # # # # # # # ########### # # # # # # # 
 # # # # # # #             # # # # # # # 
 # # # # # # ############### # # # # # # 
 # # # # # #                 # # # # # # 
 # # # # # ################### # # # # # 
 # # # # #                     # # # # # 
 # # # # ####################### # # # # 
 # # # #                         # # # # 
 # # # ########################### # # # 
 # # #                             # # # 
 # # ############################### # # 
 # #                                 # # 
 # ################################### # 
 #                                     # 
 ####################################### 
                                         
```
Note the extra wrapper of spaces on all 4 sides of the grid. That should be the area we are trying to reach, as any outward movement in that wrapper should move us out of bounds and throw the necessary error needed to get the flag.

But how do we get out of these concentric walls?

Well, there's one last part to the challenge. Remember how we're given `random.nextDouble` outputs? This is where that finally comes into play.

```java
for (int n2 = 0; n2 < 10; ++n2) {
    final int bound = 3 + n2 * 4;
    final int nextInt = random.nextInt(bound);
    switch (random.nextInt(4)) {
        case 0: {
            maze[20 + bound / 2][20 - bound / 2 + nextInt] = ' ';
            break;
        }
        case 1: {
            maze[20 - bound / 2 + nextInt][20 + bound / 2] = ' ';
            break;
        }
        case 2: {
            maze[20 - bound / 2][20 - bound / 2 + nextInt] = ' ';
            break;
        }
        case 3: {
            maze[20 - bound / 2 + nextInt][20 - bound / 2] = ' ';
            break;
        }
    }
}
```
(Oh, and the last line just sets `maze[20][20]` to the player)
```java
maze[20][20] = 'X';
```

Anyways, back to the random part. We loop 10 times, and each time, we generate a random number from a calculated bound. We also generate another rounded number bounded by 4, and from that number, we set a different part of the `maze` matrix to an empty `' '`.

Since I didn't want to go through the effort of reversing exacty that the calculations of bound meant, I just moved the maze printing statement to be right after this loop instead. (Remember to leave the if statement behind, as it's used to initialize the empty squares).
```java
public static void initMap() {
    System.out.println("I've learned from my mistakes and this time I will construct a full maze you will never be able to break out of!!!");
    maze = new char[41][41];
    for (int i = 1; i <= 20; ++i) {
        if (i % 2 == 1) {
            for (int j = 20 - i; j <= 20 + i; ++j) {
                for (int k = 20 - i; k <= 20 + i; ++k) {
                    if (j == 20 - i || j == 20 + i || k == 20 - i || k == 20 + i) {
                        maze[j][k] = '#';
                    }
                }
            }
        }
    }
    for (int l = 0; l < maze.length; ++l) {
        for (int n = 0; n < maze[l].length; ++n) {
            if (maze[l][n] != '#') {
                maze[l][n] = ' ';
            }
        }
    }
    for (int n2 = 0; n2 < 10; ++n2) {
        final int bound = 3 + n2 * 4;
        final int nextInt = random.nextInt(bound);
        switch (random.nextInt(4)) {
            case 0: {
                maze[20 + bound / 2][20 - bound / 2 + nextInt] = ' ';
                break;
            }
            case 1: {
                maze[20 - bound / 2 + nextInt][20 + bound / 2] = ' ';
                break;
            }
            case 2: {
                maze[20 - bound / 2][20 - bound / 2 + nextInt] = ' ';
                break;
            }
            case 3: {
                maze[20 - bound / 2 + nextInt][20 - bound / 2] = ' ';
                break;
            }
        }
    }
    maze[20][20] = 'X';
    for (int l = 0; l < maze.length; ++l) {
        for (int n = 0; n < maze[l].length; ++n) {
            System.out.print(maze[l][n]);
        }
        System.out.println();
    }
}
```

Running the file locally, we can now see exactly what's going on:
```terminal
$ java Maze.java
I've learned from my mistakes and this time I will construct a full maze you will never be able to break out of!!!
                                         
 ####################################### 
 #                                     # 
 # ################################### # 
 # #                                 # # 
 # # ############################### # # 
 # # #                             # # # 
 # # # ########################### # # # 
 # # # #                         # # # # 
 # # # # ####################### # # # # 
 # # # # #                     # # # # # 
 #   # # # ##### ############# # # # # # 
 # # # # # #                 # # # # # # 
 # # # # # #  ############## # # # # # # 
 # # # # # # #             # # # # # # # 
 # # # # # # # ## ######## # # # # # # # 
 # # # # # # # #         # # # # # # # # 
 # # # # # # # # ####### # # # # # # # # 
 # # # # # # # # #     # # # # # # # # # 
 # # # # # # # # # ### # # # # # # # # # 
 # # # # # # # # # #X# # # # # # # # # # 
 # # # # # # # # # # # # # # # # # # # # 
 # # # # # # # # #     # # # # # # # # # 
 # # # # # # # # # ##### # # # # # # # # 
 # # # # # # # #         # # # # # # # # 
 # # # # # # # ########### # # # # # # # 
 # # # # # # #             # # # # # # # 
 # # # # # # ############### # # # # # # 
 # # # # # #                 # # # # # # 
 # # # # # ################### # # # # # 
 # # # # #                     # # # # # 
 # # # # ####### ############### # # # # 
 # # # #                         # # # # 
 # # # ################## ######## # # # 
 # # #                             # # # 
 # # ############ ################## # # 
 # #                                 # # 
 # ################################### # 
 #                                     # 
 ########## ############################ 
                                         
```

This loop actually randomly generates holes into the walls! This means we can actually escape the maze once we're able to recover where the holes are.

Because the maze is only printed once at the beginning without the holes, we need to completely recover these holes through their random generation, and then move through each hole completely blind.

But there's just one problem: we can recover the random seed from the `nextDouble`, but how do we loop backwards to get the previously generated `nextInt`s?

### LCGs go both ways

Remember how the RNG for `java.util.Random` is defined? It's a [linear congruential generator](https://en.wikipedia.org/wiki/Linear_congruential_generator) in this form:

$$
\begin{aligned}
&m = \text{0x5DEECE66D}& \\\\
&b = \text{0xB}& \\\\
&s = \text{initial_seed}&
\end{aligned}
$$
$$
\begin{aligned}
&\text{For every call to next(bits)} \\\\
&s = ms + b \mod 2^{48} \\\\
&\text{return } s \>\> (48 - \text{bits})
\end{aligned}
$$

Because LCGs are defined as just affine ($mx+b$) functions modulo some fixed number, **they are actually reversible if you know their parameters**. In this case, Java's `Random` parameters are all publicly known, so we can easily use this to convert a reversed form of our Java Random LCG.

Mathematically, this can be done as long as we can find $m^{-1}$ in the modulus (which happens to work for Java's value of $m$):

$$
\begin{aligned}
s_1 = m{s_0} + b \mod 2^{48} \\\\
s_1 - b = m{s_0} \mod 2^{48} \\\\
m' = m^{-1} \mod 2^{48} \\\\
\frac{s_1 - b}{m} = s_0 \mod 2^{48} \\\\
m'(s_1 - b) = s_0 \mod 2^{48}
\end{aligned}
$$

Here's an example in Python:

```python
s = 123456789
m = 0x5DEECE66D
b = 0xB

inv_m = pow(m, -1, 1 << 48) # calculate m^-1 mod 2^48
print(hex(inv_m).upper()[2:])

next = (m * s + b) % (1 << 48)
print(next)
print((next - b) * inv_m % (1 << 48))

# DFE05BCB1365
# 119305093197820
# 123456789 (back to original value of seed)
```

Let's fix up our previous solve script for [random security](#random-security---452---medium). At the same time, let's also ensure it returns the value that `next` would have returned if it were called from the previous seed state (You'll see why we want this later).

 
```python
multiplier = 0x5DEECE66D
addend = 0xB
inv_mult = pow(multiplier, -1, 1 << 64)

f = <nextDouble_result> # replace this

def solve_random(f):
    state = int(float(f) * (1<<53))
    next26 = state >> 27
    next27 = state & ((1<<27)-1)

    mask = ((1<<27)-1) << (48 - 27)
    oldseedupper26 = next26 << (48 - 26) & mask
    newseedupper27 = next27 << (48 - 27) & mask
    possibleSeeds = []

    for oldseed in range(oldseedupper26, oldseedupper26 + ((1 << (48 - 26)))):
        newseed = oldseed * multiplier + addend
        newseed = newseed & ((1 << 48) - 1)
        if newseed & mask == newseedupper27:
            possibleSeeds.append(oldseed)

    if len(possibleSeeds) != 1:
        print('Error')
        exit(1)
    return possibleSeeds[0]

seed = solve_random(f)
print(seed)
```

First let's wrap the random seed cracking into its own function, as we know it already works. Then, from the seed recover, we can slowly start working backwards.

We need our `next` function again:
```python
def next(bits):
    global seed
    seed = (seed * multiplier + addend) & ((1 << 48) - 1)
    return seed >> (48 - bits)
```

Let's see how we could create a `prev` function now. We know that we have to step back using the inverse of the LCG, but we also want it to return what `next` would have returned from that random state. An easy way to do this is just to reverse once, call next, and then reverse again. No extra work required!

```python
def prev(bits): 
    global seed 
    seed = (seed - addend) * inv_mult & ((1 << 48) - 1)
    ret = next(bits)
    seed = (seed - addend) * inv_mult & ((1 << 48) - 1)
    return ret
```

Now we can remake `nextDouble` and `prevDouble` to check that we're reversing correctly:
```python
def nextDouble():
    return ((next(26) << 27) + next(27)) / (1 << 53)
def prevDouble():
    return (prev(27) + (prev(26) << 27)) / (1 << 53)
```

Just to test:
```python
# Server randomly generated numbers:
# 0.1738482973385579
# 0.31981032549992894
# 0.6341852552290427
next(1) # remember we're still in the middle of a nextDouble call
nxt_dbl = nextDouble()
nxt_nxt_dbl = nextDouble()
nxt_nxt_test = prevDouble()
nxt_test = prevDouble()

print(nxt_dbl, nxt_test)
print(nxt_nxt_dbl, nxt_nxt_test)
# 0.1738482973385579 0.1738482973385579
# 0.31981032549992894 0.31981032549992894
```

But remember, the random holes were made with `nextInt`, so we need to reverse that as well! Here's the normal `nextInt` ported to Python:
```python
def nextInt(bound):
    if bound < 0:  raise ValueError("bound must be positive")
    if bound & -bound == bound:
        return (bound * next(31)) >> 31
    
    bits = next(31)
    val = bits % bound
    while bits - val + (bound - 1) < 0:
        bits = next(31)
        val = bits % bound
    return val
```
While the loop may look hard to reverse, a dive into [Java docs](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/util/Random.html#nextInt(int)) actually reveals that this loop rarely ever rejects in the first place, so let's just replace all the `next` calls with `prev` and call it a day.
```python
def prevInt(bound):
    if bound < 0:  raise ValueError("bound must be positive")
    if bound & -bound == bound:
        return (bound * prev(31)) >> 31
    
    bits = prev(31)
    val = bits % bound
    while bits - val + (bound - 1) < 0:
        bits = prev(31)
        val = bits % bound
    return val
```

Finally, we can start reversing the holes. Remember that since the holes are generated by a for loop, we need to iterate backwards to get the correct values. On 
each loop iteration, we also need to generate the `nextInt(4)` first, and then the `nextInt(bound)`.

```python
seed = solve_random(f)
prev(1)
grid = '''
 ####################################### 
 #                                     # 
 # ################################### #
 # #                                 # # 
 # # ############################### # #
 # # #                             # # #
 # # # ########################### # # #
 # # # #                         # # # #
 # # # # ####################### # # # # 
 # # # # #                     # # # # #
 # # # # # ################### # # # # #
 # # # # # #                 # # # # # #
 # # # # # # ############### # # # # # #
 # # # # # # #             # # # # # # # 
 # # # # # # # ########### # # # # # # #
 # # # # # # # #         # # # # # # # #
 # # # # # # # # ####### # # # # # # # #
 # # # # # # # # #     # # # # # # # # #
 # # # # # # # # # ### # # # # # # # # #
 # # # # # # # # # # # # # # # # # # # # 
 # # # # # # # # # ### # # # # # # # # #
 # # # # # # # # #     # # # # # # # # #
 # # # # # # # # ####### # # # # # # # #
 # # # # # # # #         # # # # # # # #
 # # # # # # # ########### # # # # # # #
 # # # # # # #             # # # # # # #
 # # # # # # ############### # # # # # #
 # # # # # #                 # # # # # #
 # # # # # ################### # # # # #
 # # # # #                     # # # # #
 # # # # ####################### # # # #
 # # # #                         # # # #
 # # # ########################### # # #
 # # #                             # # #
 # # ############################### # #
 # #                                 # #
 # ################################### #
 #                                     #
 #######################################
 '''.splitlines()
grid = [list(line.ljust(41, ' ')) for line in grid]
print(len(grid), len(grid[0]))
for i in range(9, -1, -1):
    bound = 4*i + 3
    c = prevInt(4)
    nextint = prevInt(bound)
    print(c, nextint)
    if c == 0:
        # maze[(i8 / 2) + 20][(20 - (i8 / 2)) + nextInt] = ' ';
        grid[(bound // 2) + 20][(20 - (bound // 2)) + nextint] = ' '
    elif c == 1:
        # maze[nextInt + (20 - (i8 / 2))][(i8 / 2) + 20] = ' ';
        grid[nextint + (20 - (bound // 2))][(bound // 2) + 20] = ' '
    elif c == 2:
        # maze[20 - (i8 / 2)][(20 - (i8 / 2)) + nextInt] = ' ';
        grid[20 - (bound // 2)][(20 - (bound // 2)) + nextint] = ' '
    elif c == 3:
        # maze[nextInt + (20 - (i8 / 2))][20 - (i8 / 2)] = ' ';
        grid[nextint + (20 - (bound // 2))][20 - (bound // 2)] = ' '
```
Finally, we need some way to generate the correct path to get out. Since the holes are completely hidden on remote, I just chose to do it locally with BFS and then copy the path
over to remote.
```python
x, y = 20, 20
visited = set()
queue = [(x, y, '')]

dxyc = [
    (-1, -1, 'Q'),
    (0, -1, 'W'),
    (1, -1, 'E'),
    (-1, 0, 'A'),
    (1, 0, 'D'),
    (-1, 1, 'Z'),
    (0, 1, 'S'),
    (1, 1, 'C'),
]

while queue:
    x, y, path = queue.pop(0)
    if (x, y) in visited:
        continue
    visited.add((x, y))
    if x < 0 or x > 40 or y < 0 or y > 40:
        print(" ".join(list(path)))
        break
    if grid[y][x] == ' ':
        for dx, dy, c in dxyc:
            queue.append((x + dx, y + dy, path + c))
```
Now all we have to do it get a random number, pass it into our script, and submit the path to win!
Full script below:
```python
****multiplier = 0x5DEECE66D
addend = 0xB
inv_mult = pow(multiplier, -1, 1 << 64)

f = 0.7168512222588633 # replace this

def solve_random(f):
    state = int(float(f) * (1<<53))
    next26 = state >> 27
    next27 = state & ((1<<27)-1)

    mask = ((1<<27)-1) << (48 - 27)
    oldseedupper26 = next26 << (48 - 26) & mask
    newseedupper27 = next27 << (48 - 27) & mask
    possibleSeeds = []

    for oldseed in range(oldseedupper26, oldseedupper26 + ((1 << (48 - 26)))):
        newseed = oldseed * multiplier + addend
        newseed = newseed & ((1 << 48) - 1)
        if newseed & mask == newseedupper27:
            possibleSeeds.append(oldseed)

    if len(possibleSeeds) != 1:
        print('Error')
        exit(1)
    return possibleSeeds[0]

seed = solve_random(f)
print(seed)

def next(bits):
    global seed
    seed = (seed * multiplier + addend) & ((1 << 48) - 1)
    return seed >> (48 - bits)
def prev(bits): 
    global seed 
    seed = (seed - addend) * inv_mult & ((1 << 48) - 1)
    ret = next(bits)
    seed = (seed - addend) * inv_mult & ((1 << 48) - 1)
    return ret

def nextInt(bound):
    if bound < 0:  raise ValueError("bound must be positive")
    if bound & -bound == bound:
        return (bound * next(31)) >> 31
    
    bits = next(31)
    val = bits % bound
    while bits - val + (bound - 1) < 0:
        bits = next(31)
        val = bits % bound
    return val
def prevInt(bound):
    if bound < 0:  raise ValueError("bound must be positive")
    if bound & -bound == bound:
        return (bound * prev(31)) >> 31
    
    bits = prev(31)
    val = bits % bound
    while bits - val + (bound - 1) < 0:
        bits = prev(31)
        val = bits % bound
    return val
def nextDouble():
    return ((next(26) << 27) + next(27)) / (1 << 53)
def prevDouble():
    return (prev(27) + (prev(26) << 27)) / (1 << 53)

prev(1)
grid = '''
 ####################################### 
 #                                     # 
 # ################################### #
 # #                                 # # 
 # # ############################### # #
 # # #                             # # #
 # # # ########################### # # #
 # # # #                         # # # #
 # # # # ####################### # # # # 
 # # # # #                     # # # # #
 # # # # # ################### # # # # #
 # # # # # #                 # # # # # #
 # # # # # # ############### # # # # # #
 # # # # # # #             # # # # # # # 
 # # # # # # # ########### # # # # # # #
 # # # # # # # #         # # # # # # # #
 # # # # # # # # ####### # # # # # # # #
 # # # # # # # # #     # # # # # # # # #
 # # # # # # # # # ### # # # # # # # # #
 # # # # # # # # # # # # # # # # # # # # 
 # # # # # # # # # ### # # # # # # # # #
 # # # # # # # # #     # # # # # # # # #
 # # # # # # # # ####### # # # # # # # #
 # # # # # # # #         # # # # # # # #
 # # # # # # # ########### # # # # # # #
 # # # # # # #             # # # # # # #
 # # # # # # ############### # # # # # #
 # # # # # #                 # # # # # #
 # # # # # ################### # # # # #
 # # # # #                     # # # # #
 # # # # ####################### # # # #
 # # # #                         # # # #
 # # # ########################### # # #
 # # #                             # # #
 # # ############################### # #
 # #                                 # #
 # ################################### #
 #                                     #
 #######################################
 '''.splitlines()
grid = [list(line.ljust(41, ' ')) for line in grid]
print(len(grid), len(grid[0]))
for i in range(9, -1, -1):
    bound = 4*i + 3
    c = prevInt(4)
    nextint = prevInt(bound)
    print(c, nextint)
    if c == 0:
        # maze[(i8 / 2) + 20][(20 - (i8 / 2)) + nextInt] = ' ';
        grid[(bound // 2) + 20][(20 - (bound // 2)) + nextint] = ' '
    elif c == 1:
        # maze[nextInt + (20 - (i8 / 2))][(i8 / 2) + 20] = ' ';
        grid[nextint + (20 - (bound // 2))][(bound // 2) + 20] = ' '
    elif c == 2:
        # maze[20 - (i8 / 2)][(20 - (i8 / 2)) + nextInt] = ' ';
        grid[20 - (bound // 2)][(20 - (bound // 2)) + nextint] = ' '
    elif c == 3:
        # maze[nextInt + (20 - (i8 / 2))][20 - (i8 / 2)] = ' ';
        grid[nextint + (20 - (bound // 2))][20 - (bound // 2)] = ' '

def print_grid():
    for line in grid:
        print(''.join(line))

x, y = 20, 20
visited = set()
queue = [(x, y, '')]

dxyc = [
    (-1, -1, 'Q'),
    (0, -1, 'W'),
    (1, -1, 'E'),
    (-1, 0, 'A'),
    (1, 0, 'D'),
    (-1, 1, 'Z'),
    (0, 1, 'S'),
    (1, 1, 'C'),
]

while queue:
    x, y, path = queue.pop(0)
    if (x, y) in visited:
        continue
    visited.add((x, y))
    if x < 0 or x > 40 or y < 0 or y > 40:
        print(" ".join(list(path)))
        break
    if grid[y][x] == ' ':
        for dx, dy, c in dxyc:
            queue.append((x + dx, y + dy, path + c))
```
```terminal
$ nc 213.133.103.186 32878
*maze here*
R
Here is a random number for you since i'm nice: 0.7168512222588633
*pass into script*
Q Z S Z Z C D D D D D D C C E W W W W W W W E E W W W Q A A A A A A A A A A A Q Q A A A Z S S S S S S S S S S S S S S S S S S C D D D D D D D D D D D D D C C D D D D D E W W W W E C S S S S S S Z A A A A A A A A A A Z C D D D D D D D D D D D D E W W W W W W W W W W W W W W W W W W E E W W W W W W W W W W W W Q A A A A A A A A A A A A A A A A A A A A A A A A A A A A A A A A A A Z S S S S S S S S S S S Z Q Q
bucket{r4nd0m_n3v3r_w0rk5_e92fc72d}
```

*image writeup soon i swear*