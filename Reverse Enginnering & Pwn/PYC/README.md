# PYC

**200 Points**
**Hint:** A corrupted Python script has been discovered. The only thing we know is that it accepts an argument as input.

## Solution

### How I Solved It

#### 1. Analyzed the Bytecode Structure
The `.pyc` file was corrupted and couldn't be executed normally. I used Python's `marshal` module to extract the code objects directly from the corrupted bytecode file:

```python
import marshal

with open('challenge.pyc', 'rb') as f:
    f.read(16)  # Skip the header
    code = marshal.load(f)
```

This allowed me to inspect the code objects even though the file header was damaged.

#### 2. Decoded the Validation
By examining the bytecode constants, I found the `validate_input` function expected specific ASCII character codes:

```
(80, 89, 84, 72, 79, 78, 95, 82, 69, 86, 33)
```

Converting these to characters revealed the expected input: **"PYTHON_REV!"**

#### 3. Reverse-Engineered the Flag Generation
The `generate_flag` function performs the following operations:

- Takes the seed string: `'import os;import date;import time'`
- Computes SHA256 hash of the seed
- Extracts the first 32 hexadecimal characters
- Wraps the result in the format: `CSC26{...}`

### Flag

```
CSC26{dc6dc6c9f644ed7772e98172bd5742a5}
```

### Verification

Run the script with the discovered input:

```bash
python challenge.pyc PYTHON_REV!
```
