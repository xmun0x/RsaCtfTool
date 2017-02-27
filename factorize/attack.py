'''
RsaCrfTool-Continued-Again - Refactored and updated
author: xmunoz

RsaCtfTool-Continued - RSA CTF Cracking tool for simple CTF challenges
author: sourcekris (@CTFKris)

Original author's license below:
----------------------------------------------------------------------------
"THE BEER-WARE LICENSE" (Revision 42):
ganapati (@G4N4P4T1) wrote this file. As long as you retain this notice you
can do whatever you want with this stuff. If we meet some day, and you think
this stuff is worth it, you can buy me a beer in return.
----------------------------------------------------------------------------
'''

from Crypto.PublicKey import RSA
import signal
import gmpy2
import requests
import re
import os.path


class FactorizationError(Exception):
    pass


class PublicKey(object):
    def __init__(self, key):
        """Create RSA key from input content
           :param key: public key file content
           :type key: string
        """
        pub = RSA.importKey(key)
        self.n = pub.n
        self.e = pub.e
        self.key = key

    def prime_factors(self):
        # Factorize n using factordb.com
        try:
            url_1 = 'http://www.factordb.com/index.php?query=%i'
            url_2 = 'http://www.factordb.com/index.php?id=%s'
            r = requests.get(url_1 % self.n)
            regex = re.compile("index\.php\?id\=([0-9]+)", re.IGNORECASE)
            ids = regex.findall(r.text)
            p_id = ids[1]
            q_id = ids[2]
            regex = re.compile("value=\"([0-9]+)\"", re.IGNORECASE)
            r_1 = requests.get(url_2 % p_id)
            r_2 = requests.get(url_2 % q_id)
            self.p = int(regex.findall(r_1.text)[0])
            self.q = int(regex.findall(r_2.text)[0])
            if self.p == self.q == self.n:
                raise FactorizationError()
        except:
            raise FactorizationError()

    def __str__(self):
        # Print armored public key
        return self.key


class PrivateKey(object):
    def __init__(self, p, q, e, n):
        """Create private key from base components
           :param p: extracted from n
           :param q: extracted from n
           :param e: exponent
           :param n: n from public key
        """
        t = (p - 1) * (q - 1)
        d = long(gmpy2.invert(e, t))
        self.key = RSA.construct((n, e, d, p, q))

    def decrypt(self, cipher):
        """Uncipher data with private key
           :param cipher: input cipher
           :type cipher: string
        """
        return self.key.decrypt(cipher)

    def __str__(self):
        # Print armored private key
        return self.key.exportKey()


class RSAAttack(object):
    def __init__(self, args):
        # Load public key
        self.fname = os.path.basename(args.publickey)
        key = open(args.publickey, 'r').read()
        self.pubkeyfile = args.publickey
        self.pub_key = PublicKey(key)
        self.priv_key = None
        self.args = args
        self.unciphered = None
        if hasattr(args, "attack"):
            self.attack_name = args.attack
        else:
            self.attack_name = None
        # Load ciphertext
        if args.uncipher is not None:
            self.cipher = open(args.uncipher, 'r').read().strip()
        else:
            self.cipher = None

    def hastads(self):
        # Hastad's attack
        if self.pub_key.e == 3 and self.args.uncipher is not None:
            orig = int(self.cipher.encode("hex"), 16)
            c = orig
            while True:
                m = gmpy2.iroot(c, 3)[0]
                if pow(m, 3, self.pub_key.n) == orig:
                    s = hex(m)[2:].rstrip("L")
                    if len(s) % 2 != 0:
                        s = "0" + s
                    self.unciphered = s.decode("hex")
                    break
                c += self.pub_key.n

    def factordb(self):
        # Factors available online?
        try:
            self.pub_key.prime_factors()
            self.priv_key = PrivateKey(long(self.pub_key.p), long(self.pub_key.q),
                                       long(self.pub_key.e), long(self.pub_key.n))
        except FactorizationError:
            pass

    def wiener(self):
        # this attack module can be optional
        try:
            from wiener import WienerAttack
        except ImportError:
            if self.args.verbose:
                print("[*] Warning: Wiener attack module missing (wiener_attack.py)")
            return

        # Wiener's attack
        wiener = WienerAttack(self.pub_key.n, self.pub_key.e)
        if wiener.p is not None and wiener.q is not None:
            self.pub_key.p = wiener.p
            self.pub_key.q = wiener.q
            self.priv_key = PrivateKey(long(self.pub_key.p), long(self.pub_key.q),
                                       long(self.pub_key.e), long(self.pub_key.n))

        return

    def smallq(self):
        # Try an attack where q < 100,000, from BKPCTF2016 - sourcekris
        primes_100000 = filter(gmpy2.is_prime, range(2, 100000))
        for prime in primes_100000:
            if self.pub_key.n % prime == 0:
                self.pub_key.q = prime
                self.pub_key.p = self.pub_key.n / self.pub_key.q
                self.priv_key = PrivateKey(long(self.pub_key.p), long(self.pub_key.q),
                                           long(self.pub_key.e), long(self.pub_key.n))

        return

    def fermat(self, fermat_timeout=60):
        # Try an attack where the primes are too close together from BKPCTF2016 - sourcekris
        # this attack module can be optional
        try:
            from fermat import fermat
        except ImportError:
            if self.args.verbose:
                print("[*] Warning: Fermat factorization module missing (fermat.py)")
            return

        try:
            with Timeout(seconds=fermat_timeout):
                self.pub_key.p, self.pub_key.q = fermat(self.pub_key.n)
        except FactorizationError:
            return

        if self.pub_key.q is not None:
            self.priv_key = PrivateKey(long(self.pub_key.p), long(self.pub_key.q),
                                       long(self.pub_key.e), long(self.pub_key.n))

    def noveltyprimes(self):
        # "primes" of the form 31337 - 313333337 - see ekoparty 2015 "rsa 2070"
        # not all numbers in this form are prime but some are (25 digit is prime)
        maxlen = 25  # max number of digits in the final integer
        for i in range(maxlen - 4):
            prime = long("3133" + ("3" * i) + "7")
            if self.pub_key.n % prime == 0:
                self.pub_key.q = prime
                self.pub_key.p = self.pub_key.n / self.pub_key.q
                self.priv_key = PrivateKey(long(self.pub_key.p), long(self.pub_key.q),
                                           long(self.pub_key.e), long(self.pub_key.n))

    def commonfactors(self):
        if self.args.uncipher:
            # Try an attack where the public key has a common factor with the ciphertext
            # - sourcekris
            commonfactor = gmpy2.gcd(self.pub_key.n, int(self.cipher.encode("hex"), 16))

            if commonfactor > 1:
                self.pub_key.q = commonfactor
                self.pub_key.p = self.pub_key.n / self.pub_key.q
                self.priv_key = PrivateKey(long(self.pub_key.p), long(self.pub_key.q),
                                           long(self.pub_key.e), long(self.pub_key.n))

                self.unciphered = self.priv_key.decrypt(self.cipher)

    def commonmodulus(self):
        # NYI requires support for multiple public keys
        return

    def siqs(self):
        # attempt a Self-Initializing Quadratic Sieve
        # this attack module can be optional
        try:
            from siqs import SiqsAttack
        except ImportError:
            if self.args.verbose:
                print("[*] Warning: Yafu SIQS attack module missing (siqs.py)")
            return

        if self.pub_key.n.bit_length() > 1024:
            print("[*] Warning: Modulus too large for SIQS attack module")
            return

        siqsobj = SiqsAttack(self.args, self.pub_key.n)
        if siqsobj.checkyafu() and siqsobj.testyafu():
            siqsobj.doattack()

        if siqsobj.p and siqsobj.q:
            self.pub_key.q = siqsobj.q
            self.pub_key.p = siqsobj.p
            self.priv_key = PrivateKey(long(self.pub_key.p), long(self.pub_key.q),
                                       long(self.pub_key.e), long(self.pub_key.n))

    def attack(self, default=None):
        if self.attack_name:
            default = self.attack_name
        if default:
            print("[*] Performing " + default + " attack.")
            getattr(self, default)()
            # check and print resulting private key
            if self.priv_key is not None:
                if self.args.private:
                    print(self.priv_key)
        else:
            # loop through implemented attack methods and conduct attacks
            for attack in self.implemented_attacks:
                if self.args.verbose:
                    print("[*] Performing " + attack.__name__ + " attack.")

                getattr(self, attack.__name__)()

                # check and print resulting private key
                if self.priv_key is not None:
                    if self.args.private:
                        print(self.priv_key)
                    with open("priv-" + self.fname, "w") as f:
                        f.write(str(self.priv_key))
                    break

                if self.unciphered is not None:
                    break

        # If we wanted to decrypt, do it now
        if self.args.uncipher is not None and self.priv_key is not None:
                self.unciphered = self.priv_key.decrypt(self.cipher)
                print("[+] Clear text : %s" % self.unciphered)
        elif self.unciphered is not None:
                print("[+] Clear text : %s" % self.unciphered)
        else:
            if self.args.uncipher is not None:
                print("[-] Sorry, cracking failed")

    implemented_attacks = [hastads, factordb, noveltyprimes, smallq, wiener, commonfactors, fermat,
                           siqs]


# source http://stackoverflow.com/a/22348885
class Timeout:
    def __init__(self, seconds=10, error_message='[-] Timeout'):
        self.seconds = seconds
        self.error_message = error_message

    def handle_timeout(self, signum, frame):
        raise FactorizationError(self.error_message)

    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.seconds)

    def __exit__(self, type, value, traceback):
        signal.alarm(0)
