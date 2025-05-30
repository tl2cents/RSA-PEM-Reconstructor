from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse, long_to_bytes, getPrime
from math import ceil
from itertools import product
# extract private key info from corrutedd pem file

def generate_keypair(nbits=1024, e = 65537):
    p = getPrime(nbits//2)
    q = getPrime(nbits//2)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    dp = d % (p - 1)
    dq = d % (q - 1)
    pinv = inverse(p, q)
    return (n, e, d, p, q, dp, dq, pinv)

def gen_samples(nbits=1024, e = 65537):
    n,e,d,p,q,dp,dq,pinv = generate_keypair(nbits, e)
    # export private key
    key = RSA.construct((n, e, d))
    with open('mprivate.pem', 'wb') as f:
        f.write(key.exportKey('PEM'))
        
    # export public key
    key = RSA.construct((n, e))
    with open('mpublic.pem', 'wb') as f:
        f.write(key.exportKey('PEM'))
        
    # export private key
    key = RSA.construct((n, e, d, p, q))
    with open('mfullprivate.pem', 'wb') as f:
        f.write(key.exportKey('PEM'))
    
    # export full private key
    key = RSA.construct((n, e, d, p, q, pinv))
    with open('mfullprivate.pem', 'wb') as f:
        f.write(key.exportKey('PEM'))

# https://en.wikipedia.org/wiki/Base64
base64_table = {
    0: 'A', 1: 'B', 2: 'C', 3: 'D', 4: 'E',
    5: 'F', 6: 'G', 7: 'H', 8: 'I', 9: 'J',
    10: 'K', 11: 'L', 12: 'M', 13: 'N', 14: 'O',
    15: 'P', 16: 'Q', 17: 'R', 18: 'S', 19: 'T',
    20: 'U', 21: 'V', 22: 'W', 23: 'X', 24: 'Y',
    25: 'Z', 26: 'a', 27: 'b', 28: 'c', 29: 'd',
    30: 'e', 31: 'f', 32: 'g', 33: 'h', 34: 'i',
    35: 'j', 36: 'k', 37: 'l', 38: 'm', 39: 'n',
    40: 'o', 41: 'p', 42: 'q', 43: 'r', 44: 's',
    45: 't', 46: 'u', 47: 'v', 48: 'w', 49: 'x',
    50: 'y', 51: 'z', 52: '0', 53: '1', 54: '2',
    55: '3', 56: '4', 57: '5', 58: '6', 59: '7',
    60: '8', 61: '9', 62: '+', 63: '/'
}

base64_table_reverse = {
    'A': 0, 'B': 1, 'C': 2, 'D': 3, 'E': 4,
    'F': 5, 'G': 6, 'H': 7, 'I': 8, 'J': 9,
    'K': 10, 'L': 11, 'M': 12, 'N': 13, 'O': 14,
    'P': 15, 'Q': 16, 'R': 17, 'S': 18, 'T': 19,
    'U': 20, 'V': 21, 'W': 22, 'X': 23, 'Y': 24,
    'Z': 25, 'a': 26, 'b': 27, 'c': 28, 'd': 29,
    'e': 30, 'f': 31, 'g': 32, 'h': 33, 'i': 34,
    'j': 35, 'k': 36, 'l': 37, 'm': 38, 'n': 39,
    'o': 40, 'p': 41, 'q': 42, 'r': 43, 's': 44,
    't': 45, 'u': 46, 'v': 47, 'w': 48, 'x': 49,
    'y': 50, 'z': 51, '0': 52, '1': 53, '2': 54,
    '3': 55, '4': 56, '5': 57, '6': 58, '7': 59,
    '8': 60, '9': 61, '+': 62, '/': 63
}

der_type_dict = {
    0x02: 'INTEGER',
    0x03: 'BIT STRING',
    0x04: 'OCTET STRING',
    0x05: 'NULL',
    0x06: 'OBJECT IDENTIFIER',
    0x0c: 'UTF8String',
    0x13: 'PrintableString',
    0x14: 'TeletexString',
    0x16: 'IA5String',
    0x17: 'UTCTime',
    0x18: 'GeneralizedTime',
    0x30: 'SEQUENCE',
    0x31: 'SET',
    0xa0: 'CONTEXT SPECIFIC'
}

b64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def pemfile_to_binary(path):
    # pem to binary
    lines = open(path, 'r').readlines()
    # make sure the pem data does not contain the "begin rsa private key" and "end rsa private key" lines
    lines = lines[1:-1]
    data = "".join(lines)
    data = data.replace('\n', '')
    data = data.replace('\r', '')
    # corupted pem file contains invalid base64 characters like space or other characters
    # make sure the base64 characters in the pem data are all valid
    res = ""
    for d in data:
        if d in base64_table_reverse:
            res += bin(base64_table_reverse[d])[2:].zfill(6)
        else:
            res += '??????'
    return res

def pemfile_to_bytes(path):
    bin_data = pemfile_to_binary(path)
    if "??????" in bin_data:
        print("corrupted pem file")
        return None
    return long_to_bytes(int(bin_data, 2))

def parse_sequence(data:bytes):
    """parse ASN.1 DER sequence

    Args:
        data (bytes): ASN.1 DER bytes
    Returns:
        tuple: (length of sequence, length of value, value)
    """
    assert data[0] == 0x30
    length = data[1]
    if length & 0x80:
        st = 2+length&0x7f
        # read length
        length = int.from_bytes(data[2:2+length&0x7f], 'big')
        et = st + length
        value = data[st:et]
    else:
        st = 2
        et = st + length
        value = data[st:et]
    return length, value, data[et:]

def parse_integer(data:bytes):
    assert data[0] == 0x02
    length = data[1]
    if length & 0x80:
        st = 2+length&0x7f
        # read length
        length = int.from_bytes(data[2:2+length&0x7f], 'big')
        et = st + length
        value = int.from_bytes(data[st:et], "big")
    else:
        st = 2
        et = st + length
        value = int.from_bytes(data[st:et], "big")        
    return length, value, data[et:]


def parse_der_bytes(data:bytes):
    """ASN.1 DER bytes to format python object

    Args:
        data (bytes): ASN.1 DER bytes
    Returns:
        object: python object
    """
    # parse sequence
    all_result = []
    seq = data[:]
    while seq:
        if seq[0] == 0x30:
            _, _seq, seq = parse_sequence(seq)
            result = parse_der_bytes(_seq)
            all_result += result
        elif data[0] == 0x02:
            _, num, seq =  parse_integer(seq)
            all_result.append(num)
        else:
            raise ValueError("unknown type")
    return all_result

def parss_int_info(data:str, verbose:bool=False):
    type_info = data[0:8]
    hl_info = data[8:16]
    if verbose: print(f"[+] type  : {type_info}")
    if verbose: print(f"[+] hl: {hl_info}")
    if "?" in hl_info:
        print("[+] unknown length information")
        return None, None
    length = int(hl_info, 2)
    if length & 0x80:
        st = (2 + length&0x7f)*8
        # read length
        length_str = data[16:st]
        if "?" in length_str:
            print("[+] unknown length information")
            return None, None
        if verbose: print(f"[+] extra L-part: {length_str}")
        length = int(length_str, 2)
        et = st + length*8
    else:
        st = 16
        et = st + length*8
    if verbose: print(f"[+] length: {length}")
    if verbose: print(f"[+] read between : {(st, et)}\n\n")
    return data[st:et], data[et:]        
    
def parse_int_from_corrupted_pemfile(path:str):
    """parse integer from corrupted ASN.1 DER encoded pem file
    Args:
        path (str): path of pem file
    """
    bin_data = pemfile_to_binary(path)
    assert len(bin_data) % 8 == 0, "invalid binary data, bit missing"
    # find all integer occurences (0x02) in the binary data
    idxs = [i for i in range(0, len(bin_data), 8) if bin_data.startswith('00000010', i)]
    print(f"[+] found {idxs = } ")
    
    start_pos = idxs[0]
    int_seq = bin_data[start_pos:]
    int_info = []
    while len(int_seq) >= 16:
        r, int_seq = parss_int_info(int_seq)
        if r is None:
            return int_info
        int_info.append(r)
    return int_info

def general_rsa_key_length(n:int):
    # check n.bit_length(), close to 1024, 2048, 3072, 4096
    if n.bit_length() <= 1024:
        nbits = 1024
    elif n.bit_length() <= 2048:
        nbits = 2048
    elif n.bit_length() <= 3072:
        nbits = 3072
    elif n.bit_length() <= 4096:
        nbits = 4096
    elif n.bit_length() <= 8192:
        nbits = 8192
    else:
        assert False, "too large key size"
    dlen = (nbits // 8)
    # sometimes there is a extra zero-byte in front of the number such as 00000000 + binary_data
    plen = (nbits // 16)
    return nbits, dlen, plen

def extract_number_without_header_info(data:str, byte_len:int):
    """extract number without header information

    Args:
        data (str): binary data derived from pem file
        byte_len (int): the bytes length of the number (after encoding to binary)

    Returns:
        tuple: (header, number, remaining data)
    """
    if byte_len >= 128:
        hl = (2 + ceil(byte_len.bit_length()/8))*8
    else:
        hl = 16
    if len(data) < hl + byte_len*8:
        return None, None, data
    else:
        return data[:hl], data[hl:hl + byte_len*8], data[hl + byte_len*8:]
    
def check_intbytes_consitency(header:str, byte_len:int):
    """ Check the returned int-data(length = `byte_len`) is consistent with the header information
    Args:
        header (str): binary string mixed with '?' representing for unknown values of header information
        byte_len (int): the length of the number in bytes
    """
    if byte_len >= 128:
        extra_len = ceil(byte_len.bit_length()/8)
        b2 = bin(0x80 + extra_len)[2:].zfill(8) + bin(byte_len)[2:].zfill(extra_len * 8)
    else:
        b2 = bin(byte_len)[2:].zfill(8)
    real_binary = "00000010" + b2
    assert len(header) == len(real_binary), f"header information is not consistent with the length of the number \nhead = {header}\nreal = {real_binary}"
    for c1,c2 in zip(header, real_binary):
        if c1 == '?':
            continue
        if c1 != c2:
            return False
    return True

def parse_keyinfo_heuristic(path:str, min_nbits:int=1024, verbose:bool=True):
    """parse integer from corrupted ASN.1 DER encoded pem file
    Args:
        data (str): binary data
        min_nbits (int): minimum RSA key length (default: {1024})
        verbose (bool): verbose mode (default: {True})
    """
    bin_data = pemfile_to_binary(path)
    assert len(bin_data) % 8 == 0, "invalid binary data, bit missing"
    # find all integer occurences (0x02) in the binary data
    idxs = [i for i in range(0, len(bin_data), 8) if bin_data.startswith('00000010', i)]
    if verbose: print(f"[+] found all possible integers at {idxs = } ")
    key_info = {}
    # find n, it is the first large integer in the sequence
    for start_pos in idxs:
        int_seq = bin_data[start_pos:]
        r, int_seq = parss_int_info(int_seq)
        if "?" not in r:
            n = int(r, 2)
            if n.bit_length() >= min_nbits:
                if verbose: print(f"[+] found nstr: {r}")
                if verbose: print(f"[+] found n: {n}")
                key_info['n'] = n
                break
    # rsa key length
    nbits, dlen, plen = general_rsa_key_length(n)
    if verbose: print(f"[+] Using {nbits = } bit RSA key model")
    # find e, it is the second integer in the sequence
    if verbose: print(f"[+] {int_seq = }")
    assert "?" in int_seq[:8] or int_seq[:8] == '00000010', "invalid sequence"
    e_val, _int_seq = parss_int_info(int_seq)
    if e_val is None:
        if verbose: print("[+] unknown e value, use default value 65537")
        e = 65537
        # skip header(1) , length(1) , value (3)
        int_seq = int_seq[5:]
    else:        
        e = e_val
        if verbose: print(f"[+] found e: {e} (general value is 65537 which is 0b10000000000000001 (17 bits) )")
        int_seq = _int_seq
    key_info['e'] = e
    
    """
    The length of d, p, q, dp, dq, qi is uncertain due the existence of 00000000 in front of n,p,q,dp,dq 
    to ensure positive numbers. That's why for 1024-bit RSA, we need 129 byte to encode n and 65 byte for p and q usually.
    Therefore, I use a bruteforce method here to find all possible path
    """
    vals_order = [('d', dlen), ('p', plen), ('q', plen), ('dp', plen), ('dq', plen)] # ('qi', plen) omitted
    bf_space = product([0,1], repeat=len(vals_order))
    for incs in bf_space:
        _key_info = key_info.copy()
        valid = True
        _int_seq = int_seq[:]
        for (val_name, val_len), inc in zip(vals_order, incs):
            val_len = val_len + inc
            header, val, _int_seq = extract_number_without_header_info(_int_seq, val_len)
            if val is None:
                yield _key_info
            if check_intbytes_consitency(header, val_len):                
                _key_info[val_name] = val
                # log header information
                if verbose: print(f"[+] header information: {[header[i:i+8] for i in range(0, len(header), 8)]}, length: {val_len} bytes")
                if verbose: print(f"[+] found {val_name} = {val}\n")
            else:
                valid = False
                break
        if valid:
            if verbose: print(f"[+] found valid key information with Delta(d,p,q,dp,dq) = {incs}")
            yield _key_info
    
def check_heruistic_parser(path):
    # test heruistic parser
    print("[+] start to check correctness for complete pem file")
    key_info = parse_keyinfo_heuristic(path)
    n = key_info['n']
    e = int(key_info['e'], 2)
    d = int(key_info['d'], 2)
    p = int(key_info['p'], 2)
    q = int(key_info['q'], 2)
    dp = int(key_info['dp'], 2)
    dq = int(key_info['dq'], 2)        
    # check equations
    assert n == p*q
    assert (e*d) % ((p-1)*(q-1)) == 1
    assert d % (p-1) == dp
    assert d % (q-1) == dq
    if 'qi' in key_info:
        qi = int(key_info['qi'], 2)
        assert qi * q % p == 1 or qi * p % q == 1
    print("[+] all equations are satisfied\n\n")
    
def gen_inputs_for_rsabits(key_info, save_path="./"):
    def gen_mask(unknown_str):
        mstr = unknown_str.replace('0','1')
        mstr = mstr.replace('?','0')
        m0 = unknown_str.replace('?','0')
        m0 = int(m0,2)
        m_mask = int(mstr,2)
        return m_mask,m0
    n = key_info['n']
    nbits = general_rsa_key_length(n)[0]
    dbits = nbits
    pbits = nbits//2
    if '?' in key_info['e']:
        print("[+] Using default e value 65537")
        e = 65537
    else:
        e = int(key_info['e'], 2)
    d_mask, d0 = gen_mask(key_info['d'][-dbits:])
    p_mask, p0 = gen_mask(key_info["p"][-pbits:])
    q_mask, q0 = gen_mask(key_info["q"][-pbits:])
    dp_mask, dp0 = gen_mask(key_info["dp"][-pbits:])
    dq_mask, dq0 = gen_mask(key_info["dq"][-pbits:])
    open(save_path + "input.txt","w").write(f"{nbits}\n{n}\n{e}\n{p0}\n{q0}\n{d0}\n{dp0}\n{dq0}\n")
    open(save_path + "mask.txt","w").write(f"{p_mask}\n{q_mask}\n{d_mask}\n{dp_mask}\n{dq_mask}\n")
    
def evaluate_key_leaks(key_info:dict):
    """evaluate key leaks

    Args:
        key_info (dict): leaked key information
    """
    n = key_info['n']
    e = key_info['e']
    nbits, dlen, plen = general_rsa_key_length(n)
    vals_order = [('d', dlen), ('p', plen), ('q', plen), ('dp', plen), ('dq', plen)]  
    total_leaks = 0  
    total_bit = 0
    for val_name, val_len in vals_order:
        if val_name not in key_info:
            print(f"[+] {val_name} not found")
            continue
        if val_name == 'd':
            vbit = nbits
        else:
            vbit = nbits//2
        leak_bits_num = vbit - key_info[val_name][-vbit:].count('?')
        total_leaks += leak_bits_num
        total_bit += vbit
        print(f"[+] {leak_bits_num/vbit}% leak of {val_name}")
    print(f"[+] total leak : {total_leaks/total_bit}%")
    
def gen_leaks_dict_for_sage_solver(key_info):
    vals_order = ['d', 'p', 'q', 'dp', 'dq']
    leaks = []
    for val_name in vals_order:
        leak_dict = {}
        leak_str = key_info[val_name][::-1]
        for idx, ch in enumerate(leak_str):
            if ch != '?':
                assert ch in ['0', '1']
                leak_dict[idx] = int(ch)
        leaks.append(leak_dict)
    return leaks
    

if __name__ == "__main__":
    key_infos = list(parse_keyinfo_heuristic("./sparse.pem", verbose=False))
    print(f"[+] found {len(key_infos)} leaks model")
    for key_info in key_infos:
        n = key_info['n']
        e = 65537
        evaluate_key_leaks(key_info)
        gen_inputs_for_rsabits(key_info)
        leaks = gen_leaks_dict_for_sage_solver(key_info)
        print(f"[+] key_info = {key_info}")        
        input("> press any key to continue")