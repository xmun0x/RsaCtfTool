from Crypto.PublicKey import RSA

def create_pub(n, e):
    '''
    Create a publickey from a modulus and exponent.
    '''
    return RSA.construct((n, e)).publickey().exportKey()
