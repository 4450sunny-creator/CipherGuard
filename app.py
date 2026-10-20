import os, re, json, secrets
from pathlib import Path
from datetime import datetime, timezone
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify, abort
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidTag

ROOT=Path(__file__).resolve().parent
DATA=Path(os.environ.get("CIPHERGUARD_DATA_DIR", ROOT/"instance"))
UPLOADS=DATA/"uploads"; OUTPUTS=DATA/"outputs"; QUARANTINE=DATA/"quarantine"
for p in (DATA,UPLOADS,OUTPUTS,QUARANTINE): p.mkdir(parents=True,exist_ok=True)
MAX_BYTES=12*1024*1024
ALLOWED={".txt",".md",".csv",".json",".xml",".yaml",".yml",".ini",".cfg",".conf",".env",".py",".js",".ts",".html",".css",".sql",".log",".pdf",".docx",".xlsx",".png",".jpg",".jpeg",".zip",".bin",".dat"}
TEXT={".txt",".md",".csv",".json",".xml",".yaml",".yml",".ini",".cfg",".conf",".env",".py",".js",".ts",".html",".css",".sql",".log"}
MAGIC=b"CGD1"; SALT_LEN=16; NONCE_LEN=12; KEY_LEN=32
app=Flask(__name__)
app.config.update(SECRET_KEY=os.environ.get("CIPHERGUARD_SECRET_KEY") or secrets.token_hex(32),MAX_CONTENT_LENGTH=MAX_BYTES+1024*1024,SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE="Lax",SESSION_COOKIE_SECURE=os.environ.get("CIPHERGUARD_HTTPS")=="1")

def audit(event, details=None):
    row={"at":datetime.now(timezone.utc).isoformat(timespec="seconds"),"event":event,"details":details or {}}
    with (DATA/"audit.jsonl").open("a",encoding="utf-8") as f: f.write(json.dumps(row)+"\n")

def derive(password,salt):
    if not password or len(password)<10: raise ValueError("Use a passphrase with at least 10 characters.")
    return Scrypt(salt=salt,length=KEY_LEN,n=2**14,r=8,p=1).derive(password.encode())

def encrypt_bytes(data,password,original_name):
    salt=os.urandom(SALT_LEN); nonce=os.urandom(NONCE_LEN); key=derive(password,salt)
    # Keep the original filename inside ciphertext rather than exposing it in the header.
    name=Path(original_name.replace("\\","/")).name.encode("utf-8",errors="replace")[:255]
    payload=len(name).to_bytes(2,"big")+name+data
    header=MAGIC+bytes([1])+salt+nonce
    return header+AESGCM(key).encrypt(nonce,payload,header)

def decrypt_bytes(blob,password):
    if len(blob)<4+1+SALT_LEN+NONCE_LEN+2+16 or blob[:4]!=MAGIC or blob[4]!=1:
        raise ValueError("This is not a supported CipherGuard encrypted file.")
    off=5; salt=blob[off:off+SALT_LEN]; off+=SALT_LEN; nonce=blob[off:off+NONCE_LEN]; off+=NONCE_LEN
    header=blob[:off]
    try: payload=AESGCM(derive(password,salt)).decrypt(nonce,blob[off:],header)
    except InvalidTag as e: raise ValueError("Authentication failed. The passphrase is wrong or the encrypted file was modified.") from e
    if len(payload)<2: raise ValueError("Decrypted payload is malformed.")
    n=int.from_bytes(payload[:2],"big")
    if n>255 or len(payload)<2+n: raise ValueError("Decrypted filename metadata is malformed.")
    name=payload[2:2+n].decode("utf-8",errors="replace") or "decrypted_file"
    return payload[2+n:], secure_filename(Path(name.replace("\\","/")).name) or "decrypted_file"

RULES=[
("Private key block",re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),"critical","A private-key block may be present. If exposed, revoke or rotate the key."),
("AWS access key pattern",re.compile(r"\bAKIA[0-9A-Z]{16}\b"),"critical","This resembles an AWS access key ID. Verify it and rotate it if genuine."),
("GitHub token pattern",re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),"critical","This resembles a GitHub token. Revoke and replace it if genuine."),
("Generic secret assignment",re.compile(r"(?im)\b(?:api[_-]?key|secret|client_secret|access_token|password|passwd|token)\b\s*[:=]\s*['\"]?([^\s'\"#]{6,})"),"high","A configuration value may contain a credential. Use environment variables or a secret manager."),
("Email address",re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),"medium","Email addresses may be personal data. Confirm sharing is appropriate."),
("Indian mobile-like number",re.compile(r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)"),"medium","A number resembles an Indian mobile number. Verify context before sharing."),
("Private IPv4 address",re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"),"low","A private network address was found; this may be normal.")]
def scan_bytes(data,filename):
    if Path(filename).suffix.lower() not in TEXT:
        return {"filename":filename,"scannable":False,"message":"This file type is not scanned as text. This prototype does not deeply inspect binary or document contents.","findings":[],"bytes":len(data)}
    text=data.decode("utf-8",errors="replace"); findings=[]
    for name,pattern,severity,advice in RULES:
        matches=list(pattern.finditer(text))
        if matches:
            lines=sorted({text.count("\n",0,m.start())+1 for m in matches})[:25]
            findings.append({"rule":name,"severity":severity,"count":len(matches),"lines":lines,"recommendation":advice})
    return {"filename":filename,"scannable":True,"message":"Pattern-based scan complete. Findings are possible matches, not proof of a leak.","findings":findings,"bytes":len(data),"lines":max(1,text.count("\n")+(1 if text else 0))}
def save_upload(fs):
    original=fs.filename or "uploaded_file"; name=secure_filename(original) or "uploaded_file"
    if Path(name).suffix.lower() not in ALLOWED: raise ValueError("That file type is not supported.")
    data=fs.read(MAX_BYTES+1)
    if len(data)>MAX_BYTES: raise ValueError("Maximum upload size is 12 MB.")
    if not data: raise ValueError("The selected file is empty.")
    path=QUARANTINE/(secrets.token_hex(12)+"_"+name); path.write_bytes(data)
    return path,name,data

@app.after_request
def headers(resp):
    resp.headers.setdefault("X-Content-Type-Options","nosniff"); resp.headers.setdefault("X-Frame-Options","DENY")
    resp.headers.setdefault("Referrer-Policy","strict-origin-when-cross-origin")
    resp.headers.setdefault("Content-Security-Policy","default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; base-uri 'self'; frame-ancestors 'none'")
    return resp
@app.errorhandler(413)
def too_large(e):
    flash("Upload too large. Maximum size is 12 MB.","error"); return redirect(request.referrer or url_for("scan"))
@app.route("/")
def index(): return render_template("index.html")
@app.route("/about")
def about(): return render_template("about.html")
@app.route("/learn")
def learn(): return render_template("learn.html")
@app.route("/privacy")
def privacy(): return render_template("privacy.html")
@app.route("/scan",methods=["GET","POST"])
def scan():
    result=None
    if request.method=="POST":
        fs=request.files.get("file")
        if not fs or not fs.filename: flash("Choose a file to scan first.","error")
        else:
            try:
                _,name,data=save_upload(fs); result=scan_bytes(data,name)
                audit("file_scanned",{"filename":name,"bytes":len(data),"finding_count":len(result["findings"]),"scannable":result["scannable"]})
            except ValueError as e: flash(str(e),"error")
    return render_template("scan.html",result=result)
@app.route("/encrypt",methods=["GET","POST"])
def encrypt():
    if request.method=="POST":
        fs=request.files.get("file"); password=request.form.get("password",""); confirm=request.form.get("confirm_password","")
        if not fs or not fs.filename: flash("Choose a file to encrypt.","error")
        elif password!=confirm: flash("Passphrases do not match.","error")
        else:
            try:
                _,name,data=save_upload(fs); blob=encrypt_bytes(data,password,name)
                out=OUTPUTS/(secure_filename(name)+".cgd")
                if out.exists(): out=OUTPUTS/(Path(name).stem+"_"+secrets.token_hex(3)+".cgd")
                out.write_bytes(blob); session["download_path"]=str(out); session["download_name"]=out.name
                audit("file_encrypted",{"filename":name,"input_bytes":len(data),"output_bytes":len(blob),"algorithm":"AES-256-GCM","kdf":"scrypt"})
                flash("Encryption completed. Download your .cgd file below. Your passphrase is not stored.","success")
                return redirect(url_for("encrypt",ready="1"))
            except ValueError as e: flash(str(e),"error")
    return render_template("encrypt.html",ready=request.args.get("ready")=="1",download_name=session.get("download_name"))
@app.route("/decrypt",methods=["GET","POST"])
def decrypt():
    if request.method=="POST":
        fs=request.files.get("file"); password=request.form.get("password","")
        if not fs or not fs.filename: flash("Choose a CipherGuard .cgd file.","error")
        else:
            try:
                blob=fs.read(MAX_BYTES+4096)
                if len(blob)>MAX_BYTES+4095: raise ValueError("Encrypted file exceeds the supported size limit.")
                plain,name=decrypt_bytes(blob,password); out=OUTPUTS/("decrypted_"+secrets.token_hex(5)+"_"+name); out.write_bytes(plain)
                session["download_path"]=str(out); session["download_name"]=name
                audit("file_decrypted",{"output_bytes":len(plain),"authentication":"passed"})
                flash("Authentication passed. Download the decrypted file below.","success")
                return redirect(url_for("decrypt",ready="1"))
            except ValueError as e:
                audit("decryption_rejected",{"reason":str(e)[:100]}); flash(str(e),"error")
    return render_template("decrypt.html",ready=request.args.get("ready")=="1",download_name=session.get("download_name"))
@app.route("/download")
def download():
    pathstr=session.get("download_path")
    if not pathstr: abort(404)
    path=Path(pathstr).resolve()
    if path.parent!=OUTPUTS.resolve() or not path.exists(): abort(404)
    return send_file(path,as_attachment=True,download_name=session.get("download_name",path.name),mimetype="application/octet-stream")
@app.route("/lab")
def lab(): return render_template("lab.html")
@app.route("/api/lab/roundtrip",methods=["POST"])
def roundtrip():
    data=request.get_json(silent=True) or {}; text=str(data.get("text","CipherGuard demo")); password=str(data.get("password","Correct horse battery staple"))
    try:
        enc=encrypt_bytes(text.encode(),password,"lab.txt"); plain,_=decrypt_bytes(enc,password)
        audit("lab_roundtrip",{"result":"passed","bytes":len(plain)})
        return jsonify(ok=plain.decode()==text,message="Round-trip test passed: plaintext → ciphertext → authenticated plaintext.",original_bytes=len(text.encode()),encrypted_bytes=len(enc))
    except ValueError as e: return jsonify(ok=False,message=str(e)),400
@app.route("/api/lab/tamper",methods=["POST"])
def tamper():
    data=request.get_json(silent=True) or {}; password=str(data.get("password","Correct horse battery staple")); text=str(data.get("text","CipherGuard integrity test"))
    try:
        enc=bytearray(encrypt_bytes(text.encode(),password,"lab.txt")); enc[-1]^=1
        try: decrypt_bytes(bytes(enc),password)
        except ValueError:
            audit("lab_tamper",{"result":"detected"}); return jsonify(ok=True,message="Authentication failed as expected. Modified ciphertext was rejected.",detail="AES-GCM verifies integrity as well as confidentiality.")
        return jsonify(ok=False,message="Unexpected: modified data authenticated."),500
    except ValueError as e: return jsonify(ok=False,message=str(e)),400
@app.route("/api/health")
def health(): return jsonify(status="ok",app="CipherGuard",version="1.0.0")
@app.errorhandler(404)
def missing(e): return render_template("404.html"),404
if __name__=="__main__": app.run(host="127.0.0.1",port=int(os.environ.get("PORT","5000")),debug=False)
