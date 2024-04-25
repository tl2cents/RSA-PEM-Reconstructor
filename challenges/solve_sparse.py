import sys
sys.path.append("src")
from corrupted_pem_parser import pasrse_keyinfo_heuristic, evaluate_key_leaks, gen_inputs_for_rsabits
from reconstruct_rsa_priv import reconstructing_rsa_priv_key_iter

def prepare_input_for_rsabits(key_info):
    key_infos = list(pasrse_keyinfo_heuristic("./challenges/sparse.pem", verbose=False))
    # key_infos = list(pasrse_keyinfo_heruistic("./damaged_key.key", verbose=False))
    print(f"[+] found {len(key_infos)} leaks model")
    # the second key_info is the correct one
    for key_info in key_infos:
        n = key_info['n']
        e = 65537
        gen_inputs_for_rsabits(key_info)
        input("> you can run the rsa-bits solver now to check if the key is right")
        
def solve():
    # the following information is from the output of the rsa-bits solver
    from sage.all import PolynomialRing, Zmod
    p = 870473670805292805035827442072657874037358778401995059726246068112225672572145083696242182952028899038615354940217934488188125908120516854351411281694888625093471888014503393988647335742390662434462489597728212848995781889289518315409299978433927
    q = 46655960237331640420675539141385338215906603467667502806569876463643147953164467793954016254840326591573136961347227854024934324397296530748144773161793638227458401761418810573853865862875490305808065391572226567793909573946366690617734321500543
    n = 26191564571207865803659079386216562920365743937051163433571210679225063647091082587257715669756485899193035208469976035738059784724348440070923338255026181997563861328562376469415513279917957395542741541429134095225386135220540927874676394354088360479481955915341958270722056286102261431573282803952793459642793864316123517546752697514637037955503796798930707520651108244395501602445588782475135899939892422822256499112247770956183176429072812823174574240664993265247180146106488076712548920459190957713108289707082714400895643134613721697077267869186086353168834023098632217473990464991482806559422568127693472179449
    nbits = 2048
    known_p_lsb = 800
    pr = PolynomialRing(Zmod(n), 'x')
    x = pr.gen()
    pl800 = p % 2**known_p_lsb

    f = x * 2**known_p_lsb + pl800
    fm = f.monic()
    ub = 1024 - known_p_lsb
    roots = fm.small_roots(X=2**(ub), beta=0.48)

    if len(roots) == 0:
        print("No roots found")
    else:
        print("Roots found:")
        for root in roots:
            print(root)

    p = int(roots[0] * 2**known_p_lsb + pl800)
    q = int(n // p)
    assert p * q == n

    print(f"p = {p}")
    print(f"q = {q}")

if __name__ == "__main__":
    solve()