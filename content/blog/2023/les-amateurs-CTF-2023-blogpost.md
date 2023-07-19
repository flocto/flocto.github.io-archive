---
title: "amateursCTF 2023 Blogpost"
date: 2023-07-17T09:31:09-05:00
summary: "Some words about my experience helping with amateursCTF 2023"
tags: ["2023", "amateursCTF"]
---

The past 5 days marks the first public CTF that I've helped organize and write challenges for. It's been a really enlightening experience, beyond just seeing people ~~suffer~~ solve my challenges, I've learned a lot about the behind-the-scenes of CTFs and how they're run. 

This blogpost is here to talk about my thoughts and ideas behind my challenges, as well as a reflection over the entire experience. If you want a technical writeup for the challenges instead, please head over to the [official repo](https://github.com/les-amateurs/amateurs-ctf-2023) and view individual writeups there.

Anyway, first I'd like to go over my challenges.

## Challenges
In total I wrote 13 challenges, 10 in rev, 2 in misc, and 1 in forensics. I also helped with a few other challenges, but since I wasn't the main author for them I won't be talking about them here.

I'll start by going over the non-rev challenges, since they're a lot shorter.

### Forensics
My only challenge for Forensics was `zipper`, which was a 4 part hunt inside of a large zip file for parts of the flag. I actually started and finished this entire challenge between wave 1 and 2, after seeing how bad our forensics solve curve was, and I had two main goals with this challenge:
- Make it easy, but also not too easy
- Teach people some cool gimmicks about zip files

The gimmicks I wanted to teach included overwriting files in zips with duplicate filenames, filenames colliding with directories, and zip file comments. This is reflected in each of the parts, which are listed below in order of difficulty:
- Part 1: Comment on the entire zip file, stored in plaintext at the end of the file.
- Part 3: Comment on a specific file in the zip, stored in plaintext as well.
- Part 4: A duplicate file in the `flag/` directory, which gets overwritten with garbage data.
- Part 2: A file named `flag/`, which collides with the already existing directory and doesn't get displayed in most zip GUIs or extracted by most extractors.
I tried making Part 2 easier by attaching the Part 3 comment on one of the `flag/` names, but I guess it still wasn't enough most of the time.

The only small hiccup I didn't realize was people including `PK` inside the part 3 flag, since the compressed data header that started immediately after the comment started with `PK`, causing people to assume it was part of the flag since it was valid characters. I think this actually ended up being a good lesson though, as people should be more familiar with the zip file format anyway.

Personally I think I succeeded on both of my goals, so I'm pretty happy with the result. The challenge ended up being the second-most solved forensics, so it was balanced quite well fortunately. However, because I rushed to get this challenge out, I made a mistake setting up the zip file and left out an extra underscore, which had to be fixed after release :skull:.

### Misc
I wrote two challenges for Misc, `q-warmup` and `q-CHeSHire's game`. The Pyjails were also attributed to me, but I only help test them so I won't be talking about them here.

Anyway, my purpose for these two challenges was to teach people about Qiskit and quantum computing in general. Unfortunately, I wish I had written another challenge besides these two since the difficulty jump between these two is quite large. I also wish I had made some changes to `q-CHeSHire's game` but I'll talk about `q-warmup` first.

#### q-warmup
This challenge was supposed to be a very easy introduction to two simple quantum computing gates, the X gate and CX gate. Additionally, I made sure not to include any actual "quantum" inside this challenge, so you could actually recreate the entire quantum circuit classically and just solve from there. 

There's not really a lot to say about this challenge, it's basically a glorified easy crypto challenge, and while it ended up with a bit fewer solves than I was expecting, I think it wasn't too bad of a challenge.

#### q-CHeSHire's game
This one was much more different. I wanted to make a challenge that actually required research, then a careful analysis of the given source code. 

The challenge itself is based around the CHSH game, a famous theoretical experiement that proves that quantum entanglement cannot be explained by local hidden variables. I won't go into the details of the experiment here, but you can read more about it [here](https://en.wikipedia.org/wiki/CHSH_inequality).

Anyway, the only important fact to understand is that classically, the best winrate is 75%. With quantum entanglement, this winrate can reach 85%. 

But while trying to set up the game to be played remotely by the participants, I realized that my own implementation had a small bug that made a winrate of 87.5% possible. I decided to keep this bug in, and bump the required winrate up from 84% to 87.5%, hoping to require people to find this bug and write their own gates to exploit it. I'll leave the bug out here, but read the writeup if you want to know.

Unfortunately for me, I think all the solvers of the challenge just used the original 85% strategy and brute-forced remote until they got lucky :frowning:. I really wish this wasn't the case, but since the first blood was a brute force, I couldn't update the remote to something higher like 88% or 88.5% to discourage brute-forcing.

Anyway, if I could go back, I would probably split this challenge into two parts, one requiring the original CHSH solution and one requiring the bug. I would also make the bug more obvious, since it was quite subtle and I don't think anyone actually found it.

Update: Someone actually managed to solve with a full 100% win rate, which was amazing! They used the `z` gate to preserve information between runs and rotated the qubits if and only if the `z` phase was already applied. This was a really cool solution, and I've peeved I didn't find it earlier since I could've actually prevented any cheese from occurring.

Ending notes on Misc, overall my two challenges, while a bit unbalanced, still served their purpose. Hopefully, the Qiskit introduction wasn't too rough for most people, and they at least enjoyed solving the warmup.

### Rev
Finally, we get to the main event. I wrote 10 challenges for rev, and I'll go over each of them in the difficulty order I *originally* had planned. These won't be as detailed as the previous ones, since there's a lot more to get through.

#### volcano 
A fairly simple and easy beginner rev, all you had to do was find 2 numbers that satified both individual `volcano` and `bear` checks, while also having the same amount of digits and same digit sum. Then, you had to find a third number `m`, such that `pow(0x1337, m, volcano) == pow(0x1337, m, bear)`. 

This challenge was really simple and just meant to be a beginner rev to help ease the players into the other challenges.

#### rusteze
This one is again a very simple rev, but just in Rust. I give debug symbols, so finding main is relatively easy and from there all you had to do was follow the code and reverse the few operations. I was even nice on purpose and used while loops for every loop, so that they would be easier to read in decompilers. As long as you managed to pick out the real code among the built-in Rust pieces, this challenge shouldn't have been hard.

#### csce221
I created this challenge to teach people about GDB coredumps and how to analyze them. Now, this one was a bit messy, since I originally intended for the coredump to be analyzed in a decompiler rather than in GDB. Additionally, I edited out the parts of the coredump that described how the executable was launched, since that immediately gave away the flag. Unfortunately, this patch also prevented GDB from loading the coredump at all, meaning lots of people got stuck without even opening the coredump.

I ended up not releasing a patch to fix this, since I felt the challenge still wasn't too difficult, but I guess most people didn't know that decompilers could read coredumps, since the solve count remained way lower than I expected (instead of being 3rd like I thought it was around 5th or 6th).

#### trick question
This one is pretty much given away by its description: 
```
Which one do you hate more: decompiling pycs or reading Python bytecode disassembly? Just kidding that's a trick question.
```

The entire challenge really only has 3 main steps. First, you have to decompile the original pyc to something readable. Then, after realizing it creates a code object, you had to decompile the code object as well. Finally, the inner most part of the program is just a bunch of checks that can be reversed easily.

I even gave away a hint about decompiling marshalled code objects, but it seems most people didn't understand that I was specifically referring to something like this:
```py
check = lambda: None # any function
code = check.__code__

import marshal
marshal.dump(code, open("check.pyc", "wb"))
# Now you can use pycdc to decompile check.pyc
```

The entire point was just to teach about this technique, since it still works for the versions that are compatible with `pycdc`. In fact, if you have it patched to work with 3.11 as well, this technique should still work.

#### jsrev
Originally this challenge wasn't even planned, I only made it to troll Chip who kept asking for rev in Javascript :skull:. Anyway it's as much rev as guessctf was a legit challenge, every character of the flag is just drawn out by the balls when they spawn in, so you can just rebuild the flag pixel by pixel. Sorry for the people who got caught in the crossfire.

See the solve script for more details on the rebuilding btw.

#### headache
I wanted to create a self-modifying rev at least once, so here it is. Thanks `unvariant` for writing most of the assembly and setting up the challenge for me :smile:.
Other than being self-modifing though, this challenge doesn't have much else, basically just a bunch of z3 statements hidden by self-modifying code. Simple enough to be 5th on this list.

#### jvm
This one is actually about the same difficulty as `headache`. It's just a simple vm done in Java, except I made way too many instructions and didn't use all of them. The main check logic just shifts each character by some offset, then does a letter by letter check, so its a bit easy to brute force letter by letter. Of course, you can also just reverse the vm entirely to solve it.

#### rusteze 2
A revenge challenge to rusteze, this time compiled for Windows AND stripped of debug symbols. I also wanted to include a troll in the challenge where inputting the right password would generate the flag in memory somewhere, but it would only print out "Correct", meaning the intended solution requiring looked at parts of the code that didn't seem to be part of Rust internals but also were suspicious in how they interacted with the user input. 

Judging by some of the responses, it seems this one went well, and a lot of people were caught by the troll :joy:.

#### flagchecker
These last two challenges are both not a typical binary rev, this one being written entirely in Scratch. I wanted to do this to make harder challenges more approachable, since you didn't have to face the fear of having a decompiler spit out a bunch of unreadable code.

My inspiration for this challenge came while I was trying to get a basic ASCII converter in Scratch for a private CTF. Along the way, I figured out that making bin2dec and dec2bin were both pretty easy, and additionally xor was easy as well. This led to me choosing [TEA](https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm) as the main encryption algorithm for this challenge. 

However, when I initially finished my prototype, I found that the logic was really easy to spot and you could see the TEA Constant really easily. Thus, I decided to hand the challenge over to `HELLOPERSON` to perform his magic, and perform his magic he did. Lots of variable renaming, redefining constants, and so on. His changes made the challenge pretty much the perfect difficulty, so props to him for that. 

Solving the challenge isn't actually that hard either. At first, you could reverse some of the easier functions, like bin2dec, dec2bin, and ASCII Conversion. But, after a while, my goal was that the solver would stumble upon the TEA constant, and then realize that the entire algorithm was TEA. From there, it's just a matter of reversing the TEA algorithm, which is pretty easy.

#### 🏴❓🇨🇹🇫
Finally, the last rev challenge. This monstrosity took me a good 2 days to fully plan and develop, but honestly I had been planning on making an emojicode rev for almost a year now, so I'm glad I finally got to do it.

Anyway, while trying to think of a viable thing I could use as the rev target, I remembered the [fillomino challenge](https://capturetheflag.withgoogle.com/challenges/rev-auxin) from GoogleCTF, so I decided to do something similar and use nonograms instead, where the 1 bit would be a filled in square, and a 0 would be empty. Writing this challenge almost made me go insane, since the emojicode docs are pretty badly formatted and really hard to search through. 

Unfortunately, the way I decided to convert the input to binary was by repeatedly converting the byte value into binary, which didn't pad to 8 spaces. This meant that it was theoritically possible for two different messages to have the same binary. Originally, I had also planned for this, and crafted the message specifically so that the only one that made sense was the correct flag, but unfortunately one very sneaky duplicate still slipped through (which the first blood caught and berated me for :stuck_out_tongue:). 

As a result, I was forced to release a hint regarding the hash of the flag, which I think is fine because it's not too much information, but I still wish it could have been avoided.

### Overall challenges
Anyway, thats all the individual challenges. Overall, I think I did a okayish balancing the difficulty between each challenge, though looking back, I should have made a few more easier/medium difficulty ones.

One annoying peeve I had was answering tickets for questions that really did not require an explanation, like the many *many* people that included PK as part of their zipper flag.
Still, I think it's more important that they learn rather than be hand fed the answer, so I didn't hesitate to be mean in the tickets xd. Sorry for anyone who might have been hurt by that.

Another issue I wish I could have fixed was broken challenges. Unfortunately we didn't get enough time to do a test run of every single challenge, meaning many of my challenges were publicly released with only my solve script being proof that they were possible. 

Having testers could've made the error on `jvm` be noticed before the challenge was even released, the possible duplicate on `🏴❓🇨🇹🇫` patched, or the cheese of brute forcing `q-CHeSHire's game`. So any future chal devs out there, be sure to finish early and get people who won't be competing to test your challenges.

## Reflection on other parts
Of course, making challenges is just half of running a CTF. You also have to worry about the infra, answer tickets, manage the discord, and so on. Thankfully, `stephen` handled most of the infra issues, so I really only had to be there to answer tickets and fix any bugs that popped up.

Another thing that kept coming up was rcds/rctf being a _**PAIN**_ to work with. We probably should have borrowed Dice/TJ's private branches, since the public one was really jank.

First of all, not having any checks for what challenges are being deployed is really annoying. Every time we had to redeploy, we also had to make sure we didn't accidently include a new challenge that wasn't meant to be released. This is partially rctf's fault too, since they don't have a way to "hide" challenges, and all uploaded challenges are just immediately displayed.

This led to at least 2 instances of us having to scrap challenges completely because we accidently released them too early, or left files in the challenge.yml that should have been removed.

Secondly, I don't get what the intention of rctf was by not having the members-team structure of CTFd. It makes dealing with specific individuals a LOT easier, especially in cases of suspected cheaters. There's also no way for admins to be a separate account, instead we just had to register like a normal team and monitor the challenges that way. In my opinion, the singular admin panel that the admins get is really not enough to run an entire CTF. 

One good thing is that the [first blood monitor built by other people (orz kfb)](https://github.com/TJCSec/rctf-bloodwatch/tree/master) works really well out of the box, and the discord integration flowed nicely. I like keeping track of first bloods not just because its a great accomplishment, but it also allows us admins to monitor how process might be going on a challenge and whether or not a hint should be released.

Anyway, this is the end of my reflection! I had a ton of fun hosting this CTF, as stressful as it was, and I'm definitely open to writing for les amateurs next year. I hope you enjoyed the CTF as well, but if you suffered, then at least I hope you learned something. Remember, if you want any explanations for actually SOLVING these challenges, head over to the [official repo](https://github.com/les-amateurs/amateurs-ctf-2023/tree/master)!

Also whoever this was thanks :moyai:

![fanmail 1](/img/blog/2023/amateurs-CTF/fanmail1.png)
![fanmail 2](/img/blog/2023/amateurs-CTF/fanmail2.png)

Thanks for reading!