from sage.all import PolynomialRing, Zmod
from Crypto.Util.number import getPrime

def copper_partial_p_lsb(n, partial_p, known_p_lsb_bit, Epsilon=None, Beta=0.49):
    # the following information is from the output of the rsa-bits solver
    nbits = int(n).bit_length()
    pbits = nbits // 2
    assert known_p_lsb_bit/pbits > 0.5, f"not enough bits known for p, at least {pbits//2} bits are needed"
    pr = PolynomialRing(Zmod(n), 'x')
    x = pr.gen()
    partial_p = partial_p % 2**known_p_lsb_bit

    f = x * 2**known_p_lsb_bit + partial_p
    fm = f.monic()
    ub = 1024 - known_p_lsb_bit
    roots = fm.small_roots(X=2**(ub), epsilon=Epsilon, beta=Beta)

    if len(roots) == 0:
        print("No roots found")
        return None, None
    else:
        print("Roots found:")

    p = int(roots[0] * 2**known_p_lsb_bit + partial_p)
    q = int(n // p)
    assert p * q == n

    print(f"p = {p}")
    print(f"q = {q}")
    return p, q

def example():
    p, q = getPrime(1024), getPrime(1024)
    n = p * q
    known_p_lsb = 800
    partial_p = p % 2**known_p_lsb
    _p, _q = copper_partial_p_lsb(n, partial_p, known_p_lsb)
    if _p is not None:
        assert p == _p
        assert q == _q
        print("Success")
    else:
        print("Failed")
        
if __name__ == "__main__":
    example()