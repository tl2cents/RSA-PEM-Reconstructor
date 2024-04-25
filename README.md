
A toolkit for reconstructing the RSA private key from a corrupted pem file. The toolkit is written in pure Python and uses the sage-based library for the RSA key reconstruction. Also, I include a modified version of the open source `C++` project [Reconstructing RSA Private Keys from Random Key Bits](https://hovav.net/ucsd/papers/hs09.html) in [rsa-bits](./rsa-bits/) which is easy to use with the scripts provided.

Before using the toolkit, the corrupted pem file must contains the complete information of the rsa public key i.e. the modulus `n` and the public exponent `e`. If not, we must fix the corrupted pem file first with public key information first. 




## Structure

The structure of the repository is as follows:

- [src](./src/): 
  - [corrupted_pem_parser.py](./src/corrupted_pem_parser.py): extract all information of $p,q,d,d_p,d_q$ from the corrupted pem file. 
  - [reconstruct_rsa_priv.py](./src/reconstruct_rsa_priv.py): reconstruct the rsa private key from the extracted information based on the sage library. A python implementation of the open source project [Reconstructing RSA Private Keys from Random Key Bits](https://hovav.net/ucsd/papers/hs09.html).
  - [copper_partial_p.py](./src/copper_partial_p.py): factor the modulus $n$ with the partial leaks (least significant bits) of $p$ using the coppersmith method.
- [rsa-bits](./rsa-bits/): modified version of the open source `C++` project [Reconstructing RSA Private Keys from Random Key Bits](https://hovav.net/ucsd/papers/hs09.html). I add two extra parameters `-c C -q Q` to output the consistent information (least significant bits) of $p,q,d,d_p,d_q$ if coppersmith's method can be used. **Thus, we can handle the case that the leaked bits are not evenly distributed which is not considered in the original project.**
- [challenges](./challenges/): two CTF challengs from 2023-CTF-Zone and 2024-Geekcon CTF and the corresponding solvers.



## Usage

Prerequisites: 
- python : `python3`, `sage` and install `pycryptodome` via `pip`.
- C++ : `gmp`, `ntl` and `make`.

Some general steps of how to use the toolkit.

### Step 1 Extract key information

The pem file is base64 encoded and contains the rsa private key information. We can use [corrupted_pem_parser.py](./src/corrupted_pem_parser.py) to extract the private key information $p,q,d,d_p,d_q$ heuristically.

```python
from corrupted_pem_parser import pasrse_keyinfo_heuristic, evaluate_key_leaks
key_infos = list(pasrse_keyinfo_heuristic("corrupted.pem", verbose=False))
for key_info in key_infos:
    n = key_info['n']
    evaluate_key_leaks(key_info)
```

The output is a list of possible private key information dictionaries and there are usually up to 4 dictionaries. Then we can generate inputs for [rsa-bits](./rsa-bits/) and [reconstruct_rsa_priv.py](./src/reconstruct_rsa_priv.py).

```python 
from corrupted_pem_parser import pasrse_keyinfo_heuristic, evaluate_key_leaks
from corrupted_pem_parser import gen_inputs_for_rsabits, gen_leaks_dict_for_sage_solver
key_infos = list(pasrse_keyinfo_heuristic("corrupted.pem", verbose=False))

for key_info in key_infos:
    n = key_info['n']
    e = 65537 # if e is also corrupted
    evaluate_key_leaks(key_info)
    gen_inputs_for_rsabits(key_info)
    leaks = gen_leaks_dict_for_sage_solver(key_info)    
    res = reconstructing_rsa_priv_key(n, e, leaks)
```



### Step 2 Reconstruct the rsa private key

Generally, I recommend using the `C++` project to reconstruct the rsa private key which is much faster than python especially for large `e`. **However, if you don't want to struggle with `gmp` and `ntl` dependencies, you can use the python script.**


Build the project:

```bash
cd rsa-bits
make rsa
```

Usage :

```bash
$ ./rsa -h
Usage: rsa [OPTIONS]

        -e E    sets e to E (default is 65537)
        -n N    sets number of bits in p to N (default is 1024)
        -f F    sets fraction of known bits to F (default is .27)
        -s      omits seeding the PRNG from /dev/urandom
        -v      gives verbose output
        -t      gives timing information
        -w W    sets panic width to W (default is -1, meaning no limit)
        -i FILE reads RSA key from FILE
        -m FILE reads RSA mask of leaks from FILE
        -c C    output the partial leaks if they are good for coppersmith, C > 0.5 and default is 1.0 i.e. no coppersmith
                 if C < 1, this process will early stop when the queue size and depth meet the requirement
        -q Q    the max number of candidates in the queue to output the partial leaks, default is 1
        -h      print this message
```

In the last step, we have generated the input files `input.txt` and `mask.txt` for `rsa-bits`:

```bash
$ ./rsa -i ../out/SIGINT-input.txt -m ../out/SIGINT-mask.txt
[+] modulus bits = 2048
[+] coppersmith = off
Key found.
[+] p = 11235982333858481957738882333839552787432968413673719367565182100760999937144642883191094443194544439840950002100069215403234921117088831978729766079053709
[+] q = 11205330818639163427193816398123121286517809290248085733293742402809227671039022556356406775564617099821555918144399477278649926821357427744215089861521347
```

You can also use the python script [reconstruct_rsa_priv.py](./src/reconstruct_rsa_priv.py) to reconstruct the rsa private key.

```python
leaks = gen_leaks_dict_for_sage_solver(key_info)    
res = reconstructing_rsa_priv_key(n, e, leaks)
```



### Step 3 Use Coppersmith if needed

If the leaked bits are not evenly distributed, we can use the coppersmith method to reconstruct the private key. For challenge [GEEKCON-2024-Sparse](./challenges/sparse.pem), this is the case. We can then use the `-c C -q Q` parameters to output the partial leaks if they are good for coppersmith.

```bash
$ ./rsa -i ../out/sparse_input.txt -m ../out/sparse_mask.txt -c 0.8 -q 1
[+] modulus bits = 2048
[+] coppersmith = on
[+] coppersmith rate = 0.8
[+] max_queue = 1
[+] CopperSmith Method can be used!!!
[+] Number of leaked least significant bits of p = 820
[+] The 1th solution:
[+] p = 870473670805292805035827442072657874037358778401995059726246068112225672572145083696242182952028899038615354940217934488188125908120516854351411281694888625093471888014503393988647335742390662434462489597728212848995781889289518315409299978433927
...
```

Then use coppersmith to reconstruct the private key.



## Some Notes

I will present some notes about the principle of extracting numbers from pem file and recovering the private key.



### Extracting KEY Information

Generally, the pem file is base64 encoded and contains the RSA private key information. The private key information is stored in the following format:

```python
PrivateKeyInfo ::= SEQUENCE {
	version Version,
	privateKeyAlgorithm AlgorithmIdentifier ,
	privateKey PrivateKey,
	attributes [0] Attributes OPTIONAL
}
RSAPrivateKey ::= SEQUENCE {
	version           Version,
	modulus           INTEGER,  -- n
	publicExponent    INTEGER,  -- e
	privateExponent   INTEGER,  -- d
	prime1            INTEGER,  -- p
	prime2            INTEGER,  -- q
	exponent1         INTEGER,  -- d mod (p-1)
	exponent2         INTEGER,  -- d mod (q-1)
	coefficient       INTEGER,  -- (inverse of q) mod p
	otherPrimeInfos   OtherPrimeInfos OPTIONAL
}
```

What matters to us is all the integers in the `RSAPrivateKey` structure. We focus on the INTEGER information :

| Type (1 byte) | HL (1 byte) | Length (optional n bytes) | Data (m bytes) |
| ------------- | ----------- | ------------------------- | -------------- |

The following  describes an integer : 0x02. The `HL` describes the length of data content : the first bit of `HL` indicates whether the optional `Length` part exists.

- `HL` $\ge \text{0x8f}$ ，`HL[1:7]` is length of the optional `length`  part.
- `HL` $< \text{0x8f}$ ,  `HL[0:7]` is length of the `data`  part.

Then we can extract the `Integer` and all other type data in this way. What's more, the most significant bit of the `Integer` indicates the sign of the number. If the most significant bit is 1, the number is negative. **Thus, for 1024-bit RSA, we need 129 bytes to encode the modulus $n$ instead of 128 bytes.**



### Reconstruction of RSA Private Key

This part is based on the paper [Reconstructing RSA Private Keys from Random Key Bits](https://hovav.net/ucsd/papers/hs09.html). Given random bits of RSA private key : $p,q,d,d_p,d_q$ , we can reconstruct RSA private keys. Parameters bound （ **e must be small**, i.e. less than 32 bits）:

- $p,q$ random leak : 57% bits is required. ([Factor from random bits of p,q](https://github.com/y011d4/factor-from-random-known-bits))
- $p,q,d$ random leak ：42% bits is re required. (祥云杯 2022 leak rsa)
- $p,q,d,d_p,d_q$​ random leak ：27% bits is re required. (Plaid CTF 2014 rsa)



The idea is to prune the search space of the private key by using the known bits and equations among $n, p, q, d, d_p, d_q$ and search from the least significant bits to the most significant bits. For more details, please refer to the paper or my detailed implementation in another repository [Implementation-of-Cryptographic-Attacks](https://github.com/tl2cents/Implementation-of-Cryptographic-Attacks/tree/main/ReconstructingRSA).

What I want to emphasize is that the leaked bits are not evenly distributed in some cases but are concentrated in the least significant bits. In this case, we can recover the enough least significant bits of the prime and use the coppersmith method to recover the private key. For example, the challenge [GEEKCON-2024-Sparse](./challenges/sparse.pem) is such a case.



## Examples & Challenges

There are two challenges in the [challenges](./challenges/) directory. The first challenge [SIGINT](./challenges/sigint.pem) is from 2023-CTF-Zone and the second challenge [Sparse](./challenges/sparse.pem) is from 2024-Geekcon CTF. The corresponding solvers are in the [challenges](./challenges/) directory.


- [SIGINT-solver](./challenges/solve_sigint.py) : this solver is based on the python script and the sage library. The leaked bits are evenly distributed and we can recover the private key directly.

- [Sparse-solver](./challenges/solve_sparse.py) : this solver is based on the `C++` project and the coppersmith method. The leaked bits are not evenly distributed and we can recover the private key with the coppersmith method.


You can check the `C++` solver in the [out](./out/) directory.