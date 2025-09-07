import os, time, subprocess, sys

BASE = os.path.dirname(__file__)

def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)

def make_dummy(path, size_mb=50):
    with open(path,"wb") as f:
        block = os.urandom(1024*1024)
        for _ in range(size_mb): f.write(block)


def main():
    key = os.path.join(BASE, "demo_ed25519_private.pem")
    model = os.path.join(BASE, "dummy_model.bin")
    manifest = os.path.join(BASE, "dummy_manifest.json")

    if not os.path.exists(model):
        print("Generating 50MB dummy model..."); make_dummy(model, size_mb=50)

    print("Creating manifest...")
    p = run(["python3", os.path.join(BASE,"make_manifest.py"),
             "--file", model, "--issuer-name","Proofable Demo Issuer",
             "--privkey-pem", key, "--output", manifest, "--chunk-size","1048576"])
    print(p.stdout or p.stderr)

    p = run(["python3", os.path.join(BASE,"verify_manifest.py"),
             "--file", model, "--manifest", manifest, "--mode","fast"])
    print("FAST:", p.stdout or p.stderr)

    p = run(["python3", os.path.join(BASE,"verify_manifest.py"),
             "--file", model, "--manifest", manifest, "--mode","strict"])
    print("STRICT:", p.stdout or p.stderr)

    p = run(["python3", os.path.join(BASE,"verify_manifest.py"),
             "--file", model, "--manifest", manifest, "--mode","sample"])
    print("SAMPLE:", p.stdout or p.stderr)

if __name__ == "__main__":
    main()