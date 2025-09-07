import argparse, json, os, hashlib, base64, datetime, uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from merkle import build_merkle_root

def sha256_file(path, bufsize=1024*1024):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(bufsize)
            if not b: break
            h.update(b)
    return h.hexdigest(), os.path.getsize(path)

def load_privkey(path):
    with open(path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    return key

def pubkey_b64(privkey):
    pub = privkey.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return base64.b64encode(pub).decode()

def sign_bytes(privkey, b):
    sig = privkey.sign(b)
    return base64.b64encode(sig).decode()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", required=True)
    ap.add_argument("--issuer-name", required=True)
    ap.add_argument("--privkey-pem", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--chunk-size", type=int, default=1024*1024)
    ap.add_argument("--license", default="Proprietary")
    ap.add_argument("--safety-card-uri", default="")
    args = ap.parse_args()

    priv = load_privkey(args.privkey_pem)
    pub_b64 = pubkey_b64(priv)

    digest_hex, size_bytes = sha256_file(args.file)
    merkle_root, layers, chunk_size = build_merkle_root(args.file, chunk_size=args.chunk_size)

    manifest = {
        "version": "0.1",
        "subject": {"type":"model", "id": str(uuid.uuid4())},
        "content": {"hash_alg":"sha256","hash": digest_hex,"size_bytes": size_bytes,
                    "merkle_root": merkle_root,"chunk_size": chunk_size},
        "bom": [{"name": os.path.basename(args.file), "type":"weights", "uri": f"file://{os.path.abspath(args.file)}"}],
        "license": args.license,
        "safety_card_uri": args.safety_card_uri,
        "issuer": {"name": args.issuer_name, "key_alg":"ed25519", "pubkey": pub_b64},
        "created": datetime.datetime.utcnow().isoformat()+"Z",
        "expires": "",
        "signature": {"alg":"ed25519", "sig": ""}
    }

    to_sign = json.dumps({k:v for k,v in manifest.items() if k!="signature"}, separators=(',',":"), sort_keys=True).encode()
    manifest["signature"]["sig"] = sign_bytes(priv, to_sign)

    with open(args.output, "w") as f: json.dump(manifest, f, indent=2)
    print(f"Wrote manifest {args.output}")

if __name__ == "__main__":
    main()