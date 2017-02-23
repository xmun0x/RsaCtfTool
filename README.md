# RsaCtfTool
RSA tool for ctf - uncipher data from weak public key and try to recover private key
Automatic selection of best attack for the given public key

Attacks :
 - Weak public key factorization
 - Wiener's attack
 - Hastad's attack (Small exponent attack)
 - Small q (q<100,000)
 - Common factor between ciphertext and modulus attack
 - Fermat's factorisation for close p and q
 - Gimmicky Primes method
 - Past CTF Primes method
 - Self-Initializing Quadratic Sieve (SIQS) using Yafu - NEW
 - Common factor attacks across multiple keys - NEW

## Installation
```
pip install -r requirements.txt
```

## Usage
```
python RsaCtfToolcli.py
usage: RsaCtfToolcli.py [-h] (--publickey PUBLICKEY | --createpub)
                        [--uncipher UNCIPHER] [--verbose] [--private] [--n N]
                        [--e E]
```

Mode 1 - Attack RSA (specify --publickey)
 - publickey : public rsa key to crack. You can import multiple public keys with wildcards.
 - uncipher : cipher message to decrypt
 - private : display private rsa key if recovered

Mode 2 - Create a Public Key File Given n and e (specify --createpub)
 - n - modulus
 - e - public exponent

### Uncipher file
```
python RsaCtfToolcli.py --publickey key.pub --uncipher data.cipher 
```

### Print private key
```
python RsaCtfToolcli.py --publickey key.pub --private
```

### Generate a public key
```
python RsaCtfToolcli.py --createpub --n 7828374823761928712873129873981723 --e 65537
```

#### Todo
 - Implement multiple ciphertext handling for more attacks
 - Implement ECM factoring
 - Implement support for MultiPrime RSA (see 0ctf 2016)
 - Possibly implement Msieve support...
 - Some kind of polynomial search...
 - Brainstorm moar attack types!
 - Saw a CTF where the supplied N was a 2048 bit prime. Detect this and solve using phi = (n - 1) * (n - 1) which seemed to work for that CTF
 - Replace pycrypto dependency with [cryptography.io](https://cryptography.io/)

### Tests

Find examples of code api usage and sample data in `tests`. Run tests:

```
./runtests tests/
```
