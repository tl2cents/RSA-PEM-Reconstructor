import sys
sys.path.append("src")
from corrupted_pem_parser import pasrse_keyinfo_heuristic, evaluate_key_leaks, gen_leaks_dict_for_sage_solver
from reconstruct_rsa_priv import reconstructing_rsa_priv_key_iter


if __name__ == "__main__":
    key_infos = list(pasrse_keyinfo_heuristic("./challenges/sigint.key", verbose=False))
    # key_infos = list(pasrse_keyinfo_heruistic("./damaged_key.key", verbose=False))
    print(f"[+] found {len(key_infos)} leaks model")
    for key_info in key_infos:
        n = key_info['n']
        e = 65537
        evaluate_key_leaks(key_info)
        leaks = gen_leaks_dict_for_sage_solver(key_info)
        res = reconstructing_rsa_priv_key_iter(n, e, leaks)
        if res:
            p, q, d, dp, dq = res
            assert n == p*q, f"n != p*q"
            print(f"[+] found key: {res}")
            break