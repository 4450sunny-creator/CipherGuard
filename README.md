# CipherGuard — Data Protection Lab

Educational cybersecurity web application combining pattern-based sensitive-data discovery, authenticated file encryption, verified decryption, and an interactive cryptography lab.

## Run on Windows (PowerShell)
```powershell
cd CipherGuard
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000. If `py` is unavailable, use your installed Python executable. Example:
```powershell
& "$env:LOCALAPPDATA\\Python\\pythoncore-3.14-64\\python.exe" -m pip install -r requirements.txt
& "$env:LOCALAPPDATA\\Python\\pythoncore-3.14-64\\python.exe" app.py
```

## Run on macOS/Linux
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python app.py
```

## Pages
- `/` overview
- `/scan` pattern-based text scan
- `/encrypt` create a `.cgd` encrypted file
- `/decrypt` authenticate and decrypt a `.cgd` file
- `/lab` interactive round-trip and tampering tests
- `/about` project explanation and cartoon mind map
- `/learn` security guide
- `/privacy` storage and limitations

## Cryptography
The `.cgd` container uses AES-256-GCM authenticated encryption, fresh random salt and nonce, and Scrypt to derive a 256-bit key from a passphrase. Header metadata is authenticated as associated data. The passphrase is not intentionally stored. Losing it means this prototype cannot recover the file.

## Limits and safety
- Max upload 12 MB. Supported file extensions are defined in `app.py`.
- Scanner rules are heuristic and incomplete; it is not malware scanning or full DLP.
- Only text-like formats are scanned; binary and document contents are not deeply inspected.
- Uploaded files, generated outputs, and a metadata audit log are kept in `instance/`; this version has no automatic cleanup. Delete that folder after stopping the app to clear demo data.
- The audit log is not tamper-proof and may include filenames.
- No user authentication, CSRF protection, rate limiting, multi-user authorization, or production-grade upload sandbox is implemented.
- Do not expose Flask's development server to the public internet. Production use requires threat modeling, hardened isolation, authentication, CSRF protection, retention controls, monitoring, and independent security review.
- Keep backups before encrypting important files.

Run tests: `python -m pytest`
