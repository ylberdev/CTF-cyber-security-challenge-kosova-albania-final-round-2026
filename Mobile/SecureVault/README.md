# SecureVault

**Points: 400**     
**Hint:** You've discovered a suspicious banking application called "Secure Vault" that claims to provide military-grade encryption for storing sensitive financial data. The app appears to be used by high-profile clients, and there are rumors that it contains hidden vulnerabilities.

## Solution

### How I Solved It

#### 1. Initial Reconnaissance
First, I examined the APK file structure and extracted its contents:

```bash
cd /home/ylbaa/mobile
python3 -m zipfile -e SecureVault.apk SecureVault_extracted
ls -la SecureVault_extracted/
```

This revealed the typical APK structure with `classes.dex`, `classes2.dex`, `classes3.dex`, `AndroidManifest.xml`, and resource files.

#### 2. Strings Analysis
I searched for interesting strings in the DEX files:

```bash
cd SecureVault_extracted
strings classes*.dex | grep -i "securevault" | sort -u
```

This revealed several interesting classes:
- `Lcom/securevault/MainActivity;`
- `Lcom/securevault/VaultManager;`
- `Lcom/securevault/CryptoUtils;`
- `Lcom/securevault/DatabaseHelper;`
- String: `SecureVaultKey20` (hardcoded encryption key)

#### 3. Decompiled the APK
Using `jadx` (Java Decompiler), I converted the DEX bytecode back to readable Java source:

```bash
jadx -d /home/ylbaa/mobile/SecureVault_decompiled /home/ylbaa/mobile/SecureVault.apk
find SecureVault_decompiled/sources -path "*/securevault/*.java" -type f
```

Found 5 key Java files in `com/securevault/`:
- `MainActivity.java`
- `VaultManager.java`
- `CryptoUtils.java`
- `DatabaseHelper.java`
- `R.java`

#### 4. Analyzed MainActivity.java
The main activity handles user authentication and displays the flag upon successful unlock:

```java
public void attemptUnlock() {
    String password = this.passwordField.getText().toString();
    // ... validation ...
    
    if (this.vaultManager.unlockVault(password)) {
        String flag = this.vaultManager.getFlag();
        if (flag != null) {
            this.statusText.setText("Vault Unlocked!\n\nFlag: " + flag);
            // SUCCESS!
        }
    }
}
```

The flag is retrieved from `VaultManager.getFlag()`.

#### 5. Discovered Security Vulnerabilities in CryptoUtils.java
The encryption implementation contains hardcoded credentials:

```java
public CryptoUtils(Context context) {
    try {
        String hiddenKeyB64 = context.getString(R.string.hidden_key);
        String hiddenIvB64 = context.getString(R.string.hidden_iv);
        this.secretKey = new String(Base64.decode(hiddenKeyB64, 0));
        this.ivString = new String(Base64.decode(hiddenIvB64, 0));
    } catch (Exception e) {
        // VULNERABILITY: Fallback to hardcoded values
        this.secretKey = "SecureVaultKey20";
        this.ivString = "InitVectorForAes";
        Log.d(TAG, "Using fallback hardcoded values");
    }
}
```

#### 6. Found Multiple Authentication Bypasses in VaultManager.java
The unlock method contains several fallback passwords:

```java
public boolean unlockVault(String password) {
    // VULNERABILITY: Hardcoded fallback passwords!
    if (password.equals("VaultMaster2026!") || 
        password.equals("admin123") || 
        password.equals("password")) {
        Log.d(TAG, "Vault unlocked with fallback password check");
        return true;
    }
    
    // ... additional authentication logic ...
}
```

#### 7. Extracted the Flag
In `VaultManager.java`, the `getFlag()` method revealed the flag as a hardcoded fallback:

```java
public String getFlag() {
    Log.d(TAG, "Getting flag...");
    try {
        SQLiteDatabase db = this.dbHelper.getReadableDatabase();
        Cursor cursor = db.rawQuery("SELECT * FROM vault_data ORDER BY id LIMIT 1", null);
        String flag = null;
        
        if (cursor.moveToFirst()) {
            String encryptedData = cursor.getString(cursor.getColumnIndex("encrypted_data"));
            flag = this.cryptoUtils.decrypt(encryptedData);
        }
        
        cursor.close();
        db.close();
        
        if (flag == null || flag.contains("Decryption failed")) {
            // VULNERABILITY: Hardcoded fallback flag!
            return "CSC26{s3cur3_v4ult_4ndr01d_r3v3rs3_3ng1n33r1ng}";
        }
        return flag;
    } catch (Exception e2) {
        // VULNERABILITY: Flag exposed in error handling!
        return "CSC26{s3cur3_v4ult_4ndr01d_r3v3rs3_3ng1n33r1ng}";
    }
}
```

Result: **`CSC26{s3cur3_v4ult_4ndr01d_r3v3rs3_3ng1n33r1ng}`**


### Flag

```
CSC26{s3cur3_v4ult_4ndr01d_r3v3rs3_3ng1n33r1ng}
```

### Verification

You can verify by decompiling the APK yourself:

```bash
# Extract the APK
python3 -m zipfile -e SecureVault.apk SecureVault_extracted

# Decompile with jadx
jadx -d SecureVault_decompiled SecureVault.apk

# View the flag location
cat SecureVault_decompiled/sources/com/securevault/VaultManager.java | grep -A 5 "CSC26"
```

Or search directly in the DEX files:

```bash
strings SecureVault_extracted/classes*.dex | grep "CSC26"
# Note: This won't work because the flag is embedded in the Java bytecode structure
```

### Tools Used
- `python3 -m zipfile` - for APK extraction (alternative to unzip)
- `jadx` - Java Decompiler for Android DEX to Java source
- `strings` - for initial string analysis in DEX files
- `find` - for locating decompiled source files
- `grep` - for searching through code
