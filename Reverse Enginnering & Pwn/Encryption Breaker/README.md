# Encryption Breaker

**URL:** https://mnbvcxzasdfghjk-csc26.cybersecuritychallenge.al/  
**Hint:** An old-school arcade machine uses a custom encryption algorithm to protect its save files. Your task is to reverse engineer the encryption method and decrypt the high score data to find the hidden flag.

## Solution

### How I Solved It

#### 1. Analyzed the Encryption Structure

The challenge provided encrypted high scores with a known plaintext-ciphertext pair:
- **Plaintext:** `PLAYER1:999999`
- **Ciphertext:** `AgoXDBYFemFjYWVpWWY=`
- **Target flag:** `ERUVZ2UsczkzLAM1DjwvGCURDQ0IBQcIFB86HTFeQFZADg==`

All ciphertext ended with `=` padding, indicating **Base64 encoding** as the outer layer.

#### 2. Extracted the Key Using Known-Plaintext Attack

Using the XOR property (`plaintext ⊕ ciphertext = key`), I extracted the key pattern from the known pair:

```python
import base64

plaintext = "PLAYER1:999999"
ciphertext = base64.b64decode("AgoXDBYFemFjYWVpWWY=")

for i in range(len(plaintext)):
    key_byte = ord(plaintext[i]) ^ ciphertext[i]
    print(f"Pos {i}: 0x{key_byte:02x} = '{chr(key_byte)}'")
```

**Output:**
```
Pos 0: 0x52 = 'R'
Pos 1: 0x46 = 'F'
Pos 2: 0x56 = 'V'
Pos 3: 0x55 = 'U'
Pos 4: 0x53 = 'S'
Pos 5: 0x57 = 'W'
...
```

The first character 'R' suggested the key starts with 'R', pointing to a retro-themed key like **"RETRO"**.

#### 3. Reverse-Engineered the Rotation Algorithm

The key pattern revealed position-based rotation:

```
key_byte = (key[position % key_length] + position) % 256
```

This explained why the key didn't simply repeat - each position added an offset to the key byte.

#### 4. Implemented and Tested the Decryption

```python
def decrypt(ciphertext_b64, key):
    encrypted = base64.b64decode(ciphertext_b64)
    decrypted = []
    for i, byte in enumerate(encrypted):
        key_byte = (ord(key[i % len(key)]) + i) % 256
        decrypted.append(byte ^ key_byte)
    return bytes(decrypted)

# Test with target flag
encrypted_flag = "ERUVZ2UsczkzLAM1DjwvGCURDQ0IBQcIFB86HTFeQFZADg=="
result = decrypt(encrypted_flag, "RETRO")
print(result.decode())  # CSC26{8bit_encryption_master_2024}
```

#### 5. Found the Flag

With the correct key "RETRO" and the decryption algorithm working, the flag was successfully decrypted:

**Flag:** `CSC26{8bit_encryption_master_2024}`

### Flag

```
CSC26{8bit_encryption_master_2024}
```

### Verification

Full decryption script:

```python
import base64

def decrypt(ciphertext_b64, key):
    encrypted_bytes = base64.b64decode(ciphertext_b64)
    decrypted = []
    for i, byte in enumerate(encrypted_bytes):
        key_byte = (ord(key[i % len(key)]) + i) % 256
        decrypted.append(byte ^ key_byte)
    return bytes(decrypted).decode('utf-8')

# Verify with known plaintext
known_cipher = "AgoXDBYFemFjYWVpWWY="
print(decrypt(known_cipher, "RETRO"))  # PLAYER1:999999

# Decrypt the flag
flag_cipher = "ERUVZ2UsczkzLAM1DjwvGCURDQ0IBQcIFB86HTFeQFZADg=="
print(decrypt(flag_cipher, "RETRO"))   # CSC26{8bit_encryption_master_2024}
```

**Flag found:** `CSC26{8bit_encryption_master_2024}`
