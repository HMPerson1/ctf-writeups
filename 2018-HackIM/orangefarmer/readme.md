# Orange Farmer

## Analysis
We're given two files:

```
$ file *
field:            LLVM IR bitcode
orangefarming.so: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=b7013a35f38b802d5785de611360492ead7dad81, stripped
```

You can disassemble `field` with `llvm-dis` and look at the IR, but its contents not particularly important.
All that is relevant is that there is a function named `hello`.

Let's look at `orangefarming.so`.
It's a shared object, so there's no entry point for us to start our analysis.
(Well *technically*, there is, but it's not useful to us.)
Perhaps there's a conveniently named function?

```
[0x00037aa0]> afl
Do you want to print 2415 lines? (y/N)
```

Huh.
A quick skim of this list will tell us that, (1) this was written in C++, and (2) it uses LLVM in some fashion.
A look at the dynamic section headers confirms this:

```
$ objdump -x orangefarming.so
...snip...

Dynamic Section:
  NEEDED               libcrypto.so.1.0.0
  NEEDED               libstdc++.so.6
  NEEDED               libgcc_s.so.1
  NEEDED               libc.so.6
  RPATH                /home/machiry/tools/llvm_stuff/llvm/build/./lib

...snip...
```

(It also looks machiry left their name in here.)
Okay, but we still need to find some code to analyze.
Maybe looking at strings will help?

```
[0x00037aa0]> iz
000 0x0004c568 0x0004c568   5   8 (.rodata)  utf8 '1˗\ȥ blocks=Basic Latin,Spacing Modifier Letters,Latin Extended-B
001 0x0004c5a0 0x0004c5a0   4   5 (.rodata) ascii %02x
002 0x0004c5a8 0x0004c5a8  32  33 (.rodata) ascii a3ee1e96ee111075ea6deaa0827f1b07
003 0x0004c5c9 0x0004c5c9   9  10 (.rodata) ascii hackim18{
004 0x0004c5d8 0x0004c5d8  60  61 (.rodata) ascii /home/machiry/tools/llvm_stuff/llvm/include/llvm/ADT/ilist.h
005 0x0004c618 0x0004c618  43  44 (.rodata) ascii !empty() && "Called front() on empty list!"
006 0x0004c644 0x0004c644  27  28 (.rodata) ascii vector::_M_emplace_back_aux
007 0x0004c660 0x0004c660   6   7 (.rodata) ascii Magic!
008 0x0004c667 0x0004c667   8   9 (.rodata) ascii try-this
009 0x0004c680 0x0004c680 195 196 (.rodata) ascii NodeTy& llvm::iplist<NodeTy, Traits>::front() [with NodeTy = llvm::BasicBlock; Traits = llvm::SymbolTableListTraits<llvm::BasicBlock>; llvm::iplist<NodeTy, Traits>::reference = llvm::BasicBlock&]

...snip... (mostly llvm and libstdc++ symbols)

000 0x0005e5e0 0x0025e5e0   8   9 (.data) ascii F\\Ah\D9
001 0x0005e5ed 0x0025e5ed   4   5 (.data) ascii \afST
002 0x0005e5f2 0x0025e5f2   5   6 (.data) ascii <E\aXD
003 0x0005e5f9 0x0025e5f9  14  15 (.data) ascii oLA\vYTm\b]AU<PK
```

Ooh, there's a flag marker!
But first, what's up with that blob of random characters at 0x0025e5e0?

```
[0x00037aa0]> is. @ 0x0025e5e0
997 0x0005e5e0 0x0025e5e0 GLOBAL OBJECT   40 NULLCON_2018::OrangeFarming::flag_key

```

`flag_key`? Okay, let's make a note of that and move on to the flag marker.

```
[0x00037aa0]> axF 0x0004c5c9
Finding references of flags matching '0x0004c5c9'...
[0x0025e650-0x0025e6b0] method.NULLCON_2018::OrangeFarming.runOnModule(llvm::Module&) 0x38fdd [data] lea rsi, qword [rip + 0x135e5]
Macro 'findstref' removed.
```

This looks promising.
It's a big function, so let's start with just the parts near the "hackim18{" string and see if we can work backwards from there.

After some hand-decompiling, it looks like this:

```c++
uint64_t local_280h;
char local_2c5h;

// 0x00038fdd
std::cout << "hackim18{";
for (local_280h = 0; local_280h <= 39; local_280h++) {
  // 0x00039008
  local_2c5h = flag_key[local_280h] ^ local_50h[local_280h];
  std::cout << local_2c5h;
}
// 0x00039057
std::cout << "}" << std::endl;
```

So the `flag_key` we found earlier (how convenient) is xor'd with `local_50h` to give us the flag.
So what's in `local_50h`?
A bit of searching gives us

```c++
uint8_t local_a0h[];
char local_50h[];
uint64_t local_288h;

// 0x00038f79
sprintf(&local_50h[local_288h*2], "%02x", local_a0h[local_288h]);
```

Okay...

```c++
uint8_t local_a0h[];
SHA_CTX local_110h;

// 0x00038edb
SHA1_Final(local_a0h, &local_110h);
```

A SHA1 hash?

At this point I give up working backwards and just decompile the whole function and it's callees.

We learn that there's a `MangoGuy` class which looks like this:

```c++
class MangoGuy {
public:
  int32_t id;
  std::vector<int32_t> succs;

  static MangoGuy* bammer1()
  {
    // ...
  }
};
```

`OrangeFarming` turns out to be an `llvm::ModulePass`.
(Hmm. We're given an LLVM bitcode module.)
Looking at `OrangeFarming::runOnModule`, we see that it constructs a `std::map<int32_t, MangoGuy*>` by repeatedly calling `MangoGuy::bammer1`, which just reads from `std::cin`.
Then it iterates over all the "farms" (`llvm::Function`s) in the `llvm::Module`, looking for one that is "harvestable" (has a name that is exactly 5 characters long).
(Hey, "hello" is 5 characters long!)
It then does some initialization and calls `ragnaRock`.

`ragnaRock` performs a depth-first traversal of the control-flow graph starting at the `llvm::Function`'s entry block.
This traversal over `llvm::BasicBlock`s is performed in lock-step with a traversal over the "`MangoGuy` graph" (where each element `b` in `a.succs` represents an edge from `a` to `b`).
If at any point it finds that there's a difference between the two graphs, it returns false.
It also keeps a counter starting at 1 that's incremented every time it processes a `llvm::BasicBlock`/`MangoGuy`.
It checks that the current `MangoGuy`'s `id` is between the value of this counter and the number of `llvm::BasicBlock`s in the function (`bb_count`), returning false otherwise.
It returns true when it has completed the traversal.

If `ragnaRock` returned true, `runOnModule` computes the MD5 and SHA1 hashes of all the `MangoGuy`s (in the order visited by `ragnaRock`), and, if the MD5 hash is correct, gives us the flag using the SHA1 hash (as described earlier).

## Solving
Let's assume that `OrangeFarming` will be run on the LLVM module we're given (`field`).
We need to create a "`MangoGuy` graph" that (1) passes `ragnaRock`, and (2) has a given MD5 hash.
Once we know that, we can SHA1 hash it, xor it with `flag_key`, and get the flag.

`ragnaRock` ensures that `hello`'s CFG and our "`MangoGuy` graph" are isomorphic, so to create our "`MangoGuy` graph" it's sufficient to just assign each `llvm::BasicBlock` with an `id` and reuse the "structure" from `hello`'s CFG.

The CFG is fixed, but it seems that we'd still have to find a permutation of `id`s to satisfy the MD5 check.
However, it turns out that there is only one permutation that `ragnaRock` will accept.
Consider the last `MangoGuy` visited by `ragnaRock`.
At that point, `counter` will be equal to `bb_count`, meaning that the `MangoGuy`'s`id` must be equal to `bb_count`.
That also means that second to last `MangoGuy`'s `id` must be `bb_count - 1`, since `id`s must be unique (this is check as they're added to `guy_map`).
Then the third to last `MangoGuy`'s `id` must be `bb_count - 2`, etc.
Therefore, each `MangoGuy`'s `id` is equal to its (1-indexed) position in `guy_visit_trace`.

So all we have to do is perform the same traversal as `ragnaRock`, assign the appropriate `id` to each `llvm::BasicBlock`, hash the CFG using those `id`s, and we have the flag!
