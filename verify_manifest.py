import argparse, json, hashlib, base64, os, time, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from merkle import build_merkle_root

def verify_signature(m):
    sig_b64 = m["signature"]["sig"]; pub_b64 = m["issuer"]["pubkey"]
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64))
    to_verify = json.dumps({k:v for k,v in m.items() if k!="signature"}, separators=(",", ":"), sort_keys=True).encode()
    try:
        pub.verify(base64.b64decode(sig_b64), to_verify); return True
    except Exception: return False

def sha256_file(path, bufsize=1024*1024):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(bufsize)
            if not b: break
            h.update(b)
    return h.hexdigest(), os.path.getsize(path)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", required=True)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--mode", choices=["fast","strict","sample"], default="fast")
    ap.add_argument("--chunk-size", type=int, default=1024*1024)
    args = ap.parse_args()

    with open(args.manifest) as f: m = json.load(f)

    t0 = time.time()
    if not verify_signature(m):
        print("BLOCK: invalid signature"); sys.exit(2)
    size_ok = (os.path.getsize(args.file) == m["content"]["size_bytes"])
    t1 = time.time()

    if args.mode == "fast":
        print(f"{'ALLOW' if size_ok else 'BLOCK'}: fast_path_ms={int((t1-t0)*1000)}"); sys.exit(0 if size_ok else 3)

    if args.mode == "strict":
        digest_hex, sz = sha256_file(args.file)
        ok = (digest_hex == m['content']['hash'] and sz == m['content']['size_bytes'])
        t2 = time.time()
        print(f"{'ALLOW' if ok else 'BLOCK'}: strict_ms={int((t2-t0)*1000)}"); sys.exit(0 if ok else 3)

    if args.mode == "sample":
        root, layers, cs = build_merkle_root(args.file, chunk_size=args.chunk_size)
        ok = (root == m['content']['merkle_root'])
        t2 = time.time()
        print(f"{'ALLOW' if ok else 'BLOCK'}: merkle_ms={int((t2-t0)*1000)}"); sys.exit(0 if ok else 3)

if __name__ == "__main__":
    main()
