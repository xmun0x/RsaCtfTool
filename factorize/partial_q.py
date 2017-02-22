#!/usr/bin/python

import gmpy2

'''
Source:
https://0day.work/0ctf-2016-quals-writeups/

Based on:
RSA? Challenge in 0ctf 2016

we are given a private key masked and have the components of the
chinese remainder theorem and a partial "q"

The above writeup detailed a method to derive q candidates
given the CRT component dQ

CRT Components definition
dP    = e^-1 mod(p-1)
dQ    = e^-1 mod(q-1)
qInv  = q^-1 mod p

Equations from https://0day.work/0ctf-2016-quals-writeups/

dP Equalities
-------------
dP                 = d mod (p - 1)
dP                 = d mod (p - 1)
e * dP             = 1 mod (p - 1)
e * dP - k*(p - 1) = 1
e * dP             = 1 + k*(p-1)
e * dP -1          = k*(p-1)
(e * dP -1)/k      = (p-1)
(e * dP -1)/k +1   = p
dQ Equalities
-------------
dQ                 = d mod (q - 1)
dQ                 = d mod (q - 1)
e * dQ             = 1 mod (q - 1)
e * dQ - k*(p - 1) = 1
e * dQ             = 1 + k*(q-1)
e * dQ -1          = k*(q-1)
(e * dQ -1)/k      = (q-1)
(e * dQ -1)/k +1   = p
qInv Equalities
---------------
qInv            = q^-1 mod p
q * qInv        = 1 (mod p)
q * qInv - k*p  = 1            (For some value "k")
q * qInv        = 1 + k*p
q * qInv - 1    = k*p
(q * qInv -1)/k = p
Additionally the following paper details an algorithm to generate
p and q prime candidates with just the CRT components
https://eprint.iacr.org/2004/147.pdf
'''


def partial_q(e, dp, dq, qi, part_q):
    # Tunable to search longer
    N = 100000

    for j in range(N, 1, -1):
        q = (e * dq - 1) / j + 1
        if str(hex(q)).strip('L').endswith(part_q):
            break

    for k in range(1, N, 1):
        p = (e * dp - 1) / k + 1
        try:
            m = gmpy2.invert(q, p)
            if m == qi:
                break
        except:
            pass

    print("p = " + str(p))
    print("q = " + str(q))
