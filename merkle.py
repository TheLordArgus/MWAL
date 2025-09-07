import hashlib
def chunk_hashes(path, chunk_size=1024*1024, alg="sha256"):
    h = getattr(hashlib, alg)
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk: break
            yield h(chunk).digest()

def build_merkle_root(path, chunk_size=1024*1024, alg="sha256"):
    leaves = list(chunk_hashes(path, chunk_size, alg))
    if not leaves: return getattr(hashlib, alg)(b"\x00").hexdigest(), [], chunk_size
    layers = [leaves]; h = getattr(hashlib, alg)
    while len(layers[-1]) > 1:
        prev = layers[-1]; nxt = []
        for i in range(0, len(prev), 2):
            left = prev[i]; right = prev[i+1] if i+1 < len(prev) else prev[i]
            nxt.append(h(left+right).digest())
        layers.append(nxt)
    return layers[-1][0].hex(), layers, chunk_size
