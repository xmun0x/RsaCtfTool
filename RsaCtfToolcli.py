#!/usr/bin/python
# -*- coding: utf-8 -*-

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

from factorize import RSAAttack, create_pub
import argparse
from glob import glob
import gmpy2


def main():
    parser = argparse.ArgumentParser(description='RSA CTF Tool Continued')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--publickey',
                       help='public key file. You can use wildcards for multiple keys.')
    group.add_argument('--createpub',
                       help='Take n and e from cli and just print a public key then exit',
                       action='store_true')
    parser.add_argument('--uncipher', help='uncipher a file', default=None)
    parser.add_argument('--verbose', help='verbose mode (display n, e, p and q)',
                        action='store_true')
    parser.add_argument('--private', help='Display private key if recovered',
                        action='store_true')
    parser.add_argument('--attack', help='Name of the attack to deploy.')
    parser.add_argument('--n', type=long, help='Specify the modulus in --createpub mode.')
    parser.add_argument('--e', type=long, help='Specify the public exponent in --createpub mode.')

    args = parser.parse_args()

    # if createpub mode generate public key then quit
    if args.createpub:
        if args.n is None or args.e is None:
            raise Exception("Specify both a modulus and exponent on the command line. \
                See --help for info.")
        print(create_pub(args.n, args.e))
    # Multi Key case
    elif '*' in args.publickey or '?' in args.publickey:
        # do multikey stuff
        pubkeyfilelist = glob(args.publickey)
        if args.verbose:
            print("[*] Multikey mode is EXPERIMENTAL.")
            print("[*] Keys: " + repr(pubkeyfilelist))

        # naive case, just iterate the public keys
        attackobjs = []
        for p in pubkeyfilelist:
            if args.verbose:
                print("[*] Attacking key: " + p)
            args.publickey = p  # bit kludgey yes
            # build a list of attackobjects along the way
            attackobjs.append(RSAAttack(args))
            attackobjs[-1].attack()

        # check our array of RSAAttack objects then perform common factor
        # attacks
        if args.verbose:
            print("[*] Performing multi key attacks.")
        for x in attackobjs:
            for y in attackobjs:
                if x.pub_key.n != y.pub_key.n:
                    g = gmpy2.gcd(x.pub_key.n, y.pub_key.n)
                    if g != 1:
                        # TODO: Finish this :P
                        print(g)
                        print(x.pub_key.n)
                        print(y.pub_key.n)
                        print("[*] Found common factor in modulus for " \
                            + x.pubkeyfile + " and " + y.pubkeyfile)
    else:
        # Single key case
        attackobj = RSAAttack(args)
        attackobj.attack()


if __name__ == "__main__":
    main()
