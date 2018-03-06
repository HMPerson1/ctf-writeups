# RedVelvet

## Analysis
If we look at the disassembly for `main`, we can see that first it loads a long ASCII string onto the stack.
It turns out this is the hex-encoded SHA-256 of the flag, but we'll get back to that later.

```
0x004011c3      48b830613433.  movabs rax, 0x3634663533346130
0x004011cd      48894590       mov qword [local_70h], rax
0x004011d1      48b832383862.  movabs rax, 0x3761356262383832
0x004011db      48894598       mov qword [local_68h], rax
0x004011df      48b836346431.  movabs rax, 0x6163663331643436
0x004011e9      488945a0       mov qword [local_60h], rax
0x004011ed      48b836633930.  movabs rax, 0x3733643130396336
0x004011f7      488945a8       mov qword [local_58h], rax
0x004011fb      48b835306365.  movabs rax, 0x6633376565633035
0x00401205      488945b0       mov qword [local_50h], rax
0x00401209      48b864373638.  movabs rax, 0x3765633938363764
0x00401213      488945b8       mov qword [local_48h], rax
0x00401217      48b839656636.  movabs rax, 0x6630636436666539
0x00401221      488945c0       mov qword [local_40h], rax
0x00401225      48b866386633.  movabs rax, 0x3565303833663866
0x0040122f      488945c8       mov qword [local_38h], rax
```

Then it prints the prompt `"Your flag : "` (using `printf` for some reason) and then reads 26 bytes from stdin onto the stack.
(`fgets` will put `'\0'` into the last byte.)
Our input is saved starting at `rbp-0x100`.
Let's call that `input`.

```
0x0040125a      bfd0164000     mov edi, str.Your_flag_:    ; 0x4016d0 ; "Your flag : " ; const char * format
0x0040125f      b800000000     mov eax, 0
0x00401264      e847f5ffff     call sym.imp.printf         ; int printf(const char *format)
0x00401269      488b15200e20.  mov rdx, qword [obj.stdin]  ; loc.stdin ; [0x602090:8]=0 ; FILE *stream
0x00401270      488d8500ffff.  lea rax, qword rbp - 0x100
0x00401277      be1b000000     mov esi, 0x1b               ; 27 ; int size
0x0040127c      4889c7         mov rdi, rax                ; char *s
0x0040127f      e86cf5ffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
```

It then calls `func1` with `rbp-0x100` and `rbp-0xff`, aka `input[0]` and `input[1]`.
The return value is saved to `rbp-0x1b4`, but is never read.

```
0x00401292      0fb68501ffff.  movzx eax, byte [local_ffh]
0x00401299      0fbed0         movsx edx, al
0x0040129c      0fb68500ffff.  movzx eax, byte [local_100h]
0x004012a3      0fbec0         movsx eax, al
0x004012a6      89d6           mov esi, edx
0x004012a8      89c7           mov edi, eax
0x004012aa      e8d7f6ffff     call sym.func1
0x004012af      89854cfeffff   mov dword [local_1b4h], eax
```

If we look at `func1`, it does some math with its arguments, and if the result is some constant and our inputs were within some range, it prints `"HAPPINESS:)"` and returns. Otherwise, it `exit`s.
(Also I think they never put a return value in here, since usually the compiler will load it into `rax` right before returning, but that doesn't happen here.)

```
/ (fcn) sym.func1 126
|   sym.func1 ();
|           ; var int local_18h @ rbp-0x18
|           ; var int local_14h @ rbp-0x14
|           ; var int local_4h @ rbp-0x4
|              ; CALL XREF from 0x004012aa (main)
|           0x00400986      55             push rbp
|           0x00400987      4889e5         mov rbp, rsp
|           0x0040098a      4883ec20       sub rsp, 0x20
|           0x0040098e      89fa           mov edx, edi
|           0x00400990      89f0           mov eax, esi
|           0x00400992      8855ec         mov byte [local_14h], dl
|           0x00400995      8845e8         mov byte [local_18h], al
|           0x00400998      0fb645ec       movzx eax, byte [local_14h]
|           0x0040099c      3245e8         xor al, byte [local_18h]
|           0x0040099f      0fbed0         movsx edx, al
|           0x004009a2      0fb645e8       movzx eax, byte [local_18h]
|           0x004009a6      3245ec         xor al, byte [local_14h]
|           0x004009a9      0fbec0         movsx eax, al
|           0x004009ac      01c2           add edx, eax
|           0x004009ae      0fbe45ec       movsx eax, byte [local_14h]
|           0x004009b2      0fafd0         imul edx, eax
|           0x004009b5      0fbe45e8       movsx eax, byte [local_18h]
|           0x004009b9      29c2           sub edx, eax
|           0x004009bb      89d0           mov eax, edx
|           0x004009bd      8945fc         mov dword [local_4h], eax
|           0x004009c0      817dfc6a2a00.  cmp dword [local_4h], 0x2a6a ; [0x2a6a:4]=-1
|       ,=< 0x004009c7      752e           jne 0x4009f7
|       |   0x004009c9      807dec55       cmp byte [local_14h], 0x55  ; [0x55:1]=255 ; 'U' ; 85
|      ,==< 0x004009cd      7e1e           jle 0x4009ed
|      ||   0x004009cf      807dec5f       cmp byte [local_14h], 0x5f  ; [0x5f:1]=255 ; '_' ; 95
|     ,===< 0x004009d3      7f18           jg 0x4009ed
|     |||   0x004009d5      807de860       cmp byte [local_18h], 0x60  ; [0x60:1]=255 ; '`' ; 96
|    ,====< 0x004009d9      7e12           jle 0x4009ed
|    ||||   0x004009db      807de86f       cmp byte [local_18h], 0x6f  ; [0x6f:1]=255 ; 'o' ; 111
|   ,=====< 0x004009df      7f0c           jg 0x4009ed
|   |||||   0x004009e1      bfc4164000     mov edi, str.HAPPINESS:     ; 0x4016c4 ; "HAPPINESS:)" ; const char * s
|   |||||   0x004009e6      e8d5fdffff     call sym.imp.puts           ; int puts(const char *s)
|  ,======< 0x004009eb      eb14           jmp 0x400a01
|  |````--> 0x004009ed      bf01000000     mov edi, 1                  ; int status
|  |    |   0x004009f2      e8d9fdffff     call sym.imp.exit           ; void exit(int status)
|  |    `-> 0x004009f7      bf01000000     mov edi, 1                  ; int status
|  |        0x004009fc      e8cffdffff     call sym.imp.exit           ; void exit(int status)
|  |           ; JMP XREF from 0x004009eb (sym.func1)
|  `------> 0x00400a01      90             nop
|           0x00400a02      c9             leave
\           0x00400a03      c3             ret
```

Going back to `main`, it then calls `func2(input[1], input[2])`.

```
0x004012b5      0fb68502ffff.  movzx eax, byte [local_feh]
0x004012bc      0fbed0         movsx edx, al
0x004012bf      0fb68501ffff.  movzx eax, byte [local_ffh]
0x004012c6      0fbec0         movsx eax, al
0x004012c9      89d6           mov esi, edx
0x004012cb      89c7           mov edi, eax
0x004012cd      e832f7ffff     call sym.func2
0x004012d2      898550feffff   mov dword [local_1b0h], eax
```

`func2` is again doing some math, checking the range, printing `"HAPPINESS:)"`, and returning, or exiting.

```
/ (fcn) sym.func2 79
|   sym.func2 ();
|           ; var int local_18h @ rbp-0x18
|           ; var int local_14h @ rbp-0x14
|           ; var int local_4h @ rbp-0x4
|              ; CALL XREF from 0x004012cd (main)
|           0x00400a04      55             push rbp
|           0x00400a05      4889e5         mov rbp, rsp
|           0x00400a08      4883ec20       sub rsp, 0x20
|           0x00400a0c      89fa           mov edx, edi
|           0x00400a0e      89f0           mov eax, esi
|           0x00400a10      8855ec         mov byte [local_14h], dl
|           0x00400a13      8845e8         mov byte [local_18h], al
|           0x00400a16      0fbe45ec       movsx eax, byte [local_14h]
|           0x00400a1a      0fbe4de8       movsx ecx, byte [local_18h]
|           0x00400a1e      99             cdq
|           0x00400a1f      f7f9           idiv ecx
|           0x00400a21      8955fc         mov dword [local_4h], edx
|           0x00400a24      837dfc07       cmp dword [local_4h], 7     ; [0x7:4]=-1 ; 7
|       ,=< 0x00400a28      751c           jne 0x400a46
|       |   0x00400a2a      807de85a       cmp byte [local_18h], 0x5a  ; [0x5a:1]=255 ; 'Z' ; 90
|      ,==< 0x00400a2e      7e0c           jle 0x400a3c
|      ||   0x00400a30      bfc4164000     mov edi, str.HAPPINESS:     ; 0x4016c4 ; "HAPPINESS:)" ; const char * s
|      ||   0x00400a35      e886fdffff     call sym.imp.puts           ; int puts(const char *s)
|     ,===< 0x00400a3a      eb14           jmp 0x400a50
|     |`--> 0x00400a3c      bf01000000     mov edi, 1                  ; int status
|     | |   0x00400a41      e88afdffff     call sym.imp.exit           ; void exit(int status)
|     | `-> 0x00400a46      bf01000000     mov edi, 1                  ; int status
|     |     0x00400a4b      e880fdffff     call sym.imp.exit           ; void exit(int status)
|     |        ; JMP XREF from 0x00400a3a (sym.func2)
|     `---> 0x00400a50      90             nop
|           0x00400a51      c9             leave
\           0x00400a52      c3             ret
```

This continues with `func3(input[2], input[3])`, `func4(input[3]), input[4]`, etc.
`func6` through `func15` each take 3 inputs instead of 2, with `func5` getting indices 5,6,7; `func6` getting 7,8,9; etc.

```
0x00401341      0fb68507ffff.  movzx eax, byte [local_f9h]
0x00401348      0fbed0         movsx edx, al
0x0040134b      0fb68506ffff.  movzx eax, byte [local_fah]
0x00401352      0fbec8         movsx ecx, al
0x00401355      0fb68505ffff.  movzx eax, byte [local_fbh]
0x0040135c      0fbec0         movsx eax, al
0x0040135f      89ce           mov esi, ecx
0x00401361      89c7           mov edi, eax
0x00401363      e800f8ffff     call sym.func6
0x00401368      898560feffff   mov dword [local_1a0h], eax
```

After `func9` it tries to call `ptrace(PTRACE_TRACEME, 0, 1, 0)` for some reason, then, if `ptrace` returned -1, jumps to 0x401419, where the jump there *cannot* happen and so falls through to 0x40141f; otherwise it jumps directly to 0x40141f. Strange.

```
     0x004013f5      b900000000     mov ecx, 0
     0x004013fa      ba01000000     mov edx, 1
     0x004013ff      be00000000     mov esi, 0
     0x00401404      bf00000000     mov edi, 0
     0x00401409      b800000000     mov eax, 0
     0x0040140e      e80df4ffff     call sym.imp.ptrace
     0x00401413      4883f8ff       cmp rax, 0xff
 ,=< 0x00401417      7506           jne 0x40141f
,==< 0x00401419      0f84ac020000   je 0x4016cb
|`-> 0x0040141f      ...
```

Anyway, after `func1`-`func15` it takes the SHA-256 hash of `input`, hex-encodes it with `sprintf` in a loop, and compares it to the string from earlier.
(`rbp-0x178` was loaded with the address of `input` earlier.)

```
     0x0040152d      488d8590feff.  lea rax, qword rbp - 0x170
     0x00401534      4889c7         mov rdi, rax
     0x00401537      e834f3ffff     call sym.imp.SHA256_Init
     0x0040153c      488b8588feff.  mov rax, qword [local_178h]
     0x00401543      4889c7         mov rdi, rax                ; const char * s
     0x00401546      e8b5f2ffff     call sym.imp.strlen         ; size_t strlen(const char *s)
     0x0040154b      4889c2         mov rdx, rax
     0x0040154e      488b8d88feff.  mov rcx, qword [local_178h]
     0x00401555      488d8590feff.  lea rax, qword rbp - 0x170
     0x0040155c      4889ce         mov rsi, rcx
     0x0040155f      4889c7         mov rdi, rax
     0x00401562      e8c9f2ffff     call sym.imp.SHA256_Update
     0x00401567      488d9590feff.  lea rdx, qword rbp - 0x170
     0x0040156e      488d8520ffff.  lea rax, qword rbp - 0xe0
     0x00401575      4889d6         mov rsi, rdx
     0x00401578      4889c7         mov rdi, rax
     0x0040157b      e8e0f2ffff     call sym.imp.SHA256_Final
     0x00401580      c78548feffff.  mov dword [local_1b8h], 0
 ,=< 0x0040158a      eb43           jmp 0x4015cf
.--> 0x0040158c      8b8548feffff   mov eax, dword [local_1b8h]
:|   0x00401592      4898           cdqe
:|   0x00401594      0fb6840520ff.  movzx eax, byte [rbp + rax - 0xe0]
:|   0x0040159c      0fb6c0         movzx eax, al
:|   0x0040159f      8b9548feffff   mov edx, dword [local_1b8h]
:|   0x004015a5      01d2           add edx, edx
:|   0x004015a7      488d8d40ffff.  lea rcx, qword rbp - 0xc0
:|   0x004015ae      4863d2         movsxd rdx, edx
:|   0x004015b1      4801d1         add rcx, rdx                ; '('
:|   0x004015b4      89c2           mov edx, eax                ; ...
:|   0x004015b6      bedd164000     mov esi, str.02x            ; 0x4016dd ; "%02x" ; const char*
:|   0x004015bb      4889cf         mov rdi, rcx                ; char *s
:|   0x004015be      b800000000     mov eax, 0
:|   0x004015c3      e848f2ffff     call sym.imp.sprintf        ; int sprintf(char *s,
:|   0x004015c8      838548feffff.  add dword [local_1b8h], 1
:|      ; JMP XREF from 0x0040158a (main)
:`-> 0x004015cf      83bd48feffff.  cmp dword [local_1b8h], 0x1f ; [0x1f:4]=-1 ; 31
`==< 0x004015d6      7eb4           jle 0x40158c
     0x004015d8      488d5590       lea rdx, qword rbp - 0x70
     0x004015dc      488d8540ffff.  lea rax, qword rbp - 0xc0
     0x004015e3      4889d6         mov rsi, rdx                ; const char * s2
     0x004015e6      4889c7         mov rdi, rax                ; const char * s1
     0x004015e9      e862f2ffff     call sym.imp.strcmp         ; int strcmp(const char *s1, const char *s2)
```

If they're equal, it tells us we got the flag.

```
    0x004015ee      85c0           test eax, eax
,=< 0x004015f0      752f           jne 0x401621
|   0x004015f2      488b8588feff.  mov rax, qword [local_178h]
|   0x004015f9      4889c6         mov rsi, rax
|   0x004015fc      bfe2164000     mov edi, str.flag_:_____s   ; 0x4016e2 ; "flag : {\" %s \"}\n" ; const char * format
|   0x00401601      b800000000     mov eax, 0
|   0x00401606      e8a5f1ffff     call sym.imp.printf         ; int printf(const char *format)
```

## Solving
You *could* solve this by manually going through each function, reversing it, and brute-forcing its parameters, but there's a much easier way.
[angr](http://angr.io/) is a binary analysis python framework for for static and dynamic symbolic execution.
We can just throw the binary at it, tell it "try to get here", and it will execute the binary with symbolic inputs, recording what constraints the inputs must satisfy in order for execution to reach that point.
Finally, it can also solve these constraints and give you some inputs that will satisfy them, meaning those inputs will result in a certain execution of the binary.

In our case, we want those constraints on our input to be "being the flag", so we tell angr to try to get past all the checking functions.
We can't tell it to go all the way to where the binary prints out "flag : ..." because that's after the SHA-256 hash, and angr doesn't like symbolically hashing things.
(Nor should it; that's kinda the point of a cryptographically secure hash function)
Instead we tell it to stop right before the SHA-256 hash.
This *might* result in an input that fails the SHA-256 check, but the set of inputs that get that far anyway are almost certainly small enough to just brute force if needed.

So, I made a python script using angr to do what I described earlier. It takes about 7 minutes to run and then spits out the flag.

```
$ python2 angr-solve.py
WARNING | 2018-02-05 01:52:03,828 | angr.analyses.disassembly_utils | Your verison of capstone does not support MIPS instruction groups.
Starting...
past func1
past func2
past func3
past func4
past func5
past func6
past func7
past func8
past func9
WARNING | 2018-02-05 01:53:42,220 | angr.procedures.definitions | unsupported syscall: sys_101
WARNING | 2018-02-05 01:53:42,240 | angr.procedures.definitions | unsupported syscall: sys_101
WARNING | 2018-02-05 01:53:54,696 | angr.engines.successors | Exit state has over 257 possible solutions. Likely unconstrained; skipping. <BV64 reg_28_30_64>
past func10
past func11
past func12
past func13
past func14
past func15
Solving for flags...
Bruteforcing flag...
What_You_Wanna_Be?:)_la_la
Time elapsed: 429.682609081
```

And if we give that to the binary, it tells us that we have indeed  found the flag.

```
$ ./RedVelvet
Your flag : What_You_Wanna_Be?:)_la_la
HAPPINESS:)
HAPPINESS:)
HAPPINESS:)
HAPPINESS:)
HAPPINESS:)
HAPPINESS:)
HAPPINESS:)
HAPPINESS:)
HAPPINESS:)
HAPPINESS:)
HAPPINESS:)
HAPPINESS:)
HAPPINESS:)
HAPPINESS:)
HAPPINESS:)
flag : {" What_You_Wanna_Be?:)_la_la "}
```

:D
