# DESpicableMe

## Analysis

We're given a file:

```
$ file *
larrycrypt: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=99665fc5b82c4e79c73bf8506012396fa2dc8dc5, not stripped
```

and we're told that it was executed like this:

```
$ ./larrycrypt -R 4 -K "V3c70R" -m <message>
Encrypted Bits: 000101 000000 100111 011001 101110 011101 001110 101111 010001 101111 110000 001001 110010 111011 110111 010001 000100 101011 100010 100010 000001 010100 001111 010010 111110 001110 000111 
```

So presumably, we need to decrypt this back to the original message, which will give us the flag.

It looks like the organizers of this CTF were even nice enough to give us a help string for `larrycrypt`:

```
$ ./larrycrypt -h
Usage: larrycrypt [Option] <value> ...
Options:
	-R <rounds>, --rounds <rounds>: Set R, default 2
	-K <key>, --key <key>: Set key, default "Mu"
	-m <message>, --message <message>: Set message, default "MiN0n!"
```

Looking at the disassembly for main, it does some argument parsing as described by its help string.
But wait, whats this?

```
        ; JMP XREF from 0x00003b77 (main)
     0x00003bb4      488b8538ffff.  mov rax, qword [local_c8h]
     0x00003bbb      488d353e1a00.  lea rsi, qword str.key      ; 0x5600 ; "--key" ; const char * s2
     0x00003bc2      4889c7         mov rdi, rax                ; const char * s1
     0x00003bc5      e8d6d5ffff     call sym.imp.strcmp         ; int strcmp(const char *s1, const char *s2)
     0x00003bca      85c0           test eax, eax
 ┌─< 0x00003bcc      741e           je 0x3bec
 │   0x00003bce      488b8538ffff.  mov rax, qword [local_c8h]
 │   0x00003bd5      488d352a1a00.  lea rsi, qword str.k        ; 0x5606 ; "-k" ; const char * s2
 │   0x00003bdc      4889c7         mov rdi, rax                ; const char * s1
 │   0x00003bdf      e8bcd5ffff     call sym.imp.strcmp         ; int strcmp(const char *s1, const char *s2)
 │   0x00003be4      85c0           test eax, eax
┌──< 0x00003be6      0f8583000000   jne 0x3c6f
││      ; JMP XREF from 0x00003bcc (main)
│└─> 0x00003bec      488d852fffff.  lea rax, qword [local_d1h]
```

The help string says it looks for an upper case `-K`, but the program actually checks for a lower case `-k`.

**_Hmm... :thinking:_**

Anyway, after parsing arguments and validating that the message length in bits is divisible by 12, it calls `encrypt`, and prints the string it returns.

`encrypt` calls `doRounds`, which is a 12-bit Feistel block cipher similar to DES.
For the rest of this writeup, a "block" will refer to exactly 12 bits.
A "half-block" will refer to exactly 6 bits.
`encrypt` uses an, uh, *interesting* block cipher mode wherein the first half-block of the plaintext is essentially used as an IV.
The rest of the plaintext is encrypted a half-block at a time.
Note that this means that the length of the ciphertext is a half-block shorter than the length of the plaintext, so *information is lost in the encryption process*.
The high half of the input to `doRounds` is the low half from the previous `doRounds` output block and the low half of the input is the half-block of plaintext.
(For the first `doRounds`, the IV is used instead of the previous output.)
The high half of the resulting `doRounds` output block is output as the ciphertext.
The key schedule is essentially just rotating the bits of the key leftward each round and taking the first 8 bits.

## Solving

`doRounds` is a Feistel cipher, so decrypting is just encrypting with the reverse key schedule.
For each half-block outputted during encryption, the key would have been left-rotated `R` bits, where `R` is the "rounds" parameter given to `larrycrypt`.
So for decrypting, we want to start by left-rotating the key by `R`\*`c`-1 bits, where c is the number of ciphertext half-blocks, and rotate it rightward each round.

`encrypt` is not as straight-forward to invert, but the key is that the each input block to `doRounds` must be exactly what it had output during encryption, but with the high/low halves swapped.
(`doRounds` swaps the low/high halves at the end of *each* round, but a real Feistel cipher is only supposed to swap the halves *between* rounds and not after the final round.)
During encryption, part of each `doRounds` output block was used as part of the input for the next `doRounds`, so for decryption, we have to start with the last `doRounds` output block.
One complication is that we don't know what the low half of the last `doRounds` output block was, so we have to just guess.
(Technically, all possible half-blocks are "correct", i.e. all resulting plaintexts will encrypt to the ciphertext we started with. This is because this encryption method is lossy.)
Luckily, it's just 6 bits so it's trivial to just check all 64 possibilities.
Flags are always entirely printable ASCII, so it's also pretty easy to filter out most of the wrong guesses.
