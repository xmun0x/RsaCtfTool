import sys
from sympy.solvers import solve
from sympy import Symbol
from gmpy2 import isqrt, is_square

# A reimplementation of pablocelayes rsa-wiener-attack for this purpose
# https://github.com/pablocelayes/rsa-wiener-attack/


class WienerAttack(object):

    def rational_to_contfrac(self, x, y):
        a = x // y
        if a * y == x:
            return [a]
        else:
            pquotients = self.rational_to_contfrac(y, x - a * y)
            pquotients.insert(0, a)
            return pquotients

    def convergents_from_contfrac(self, frac):
        convs = []
        for i in range(len(frac)):
            convs.append(self.contfrac_to_rational(frac[0:i]))
        return convs

    def contfrac_to_rational(self, frac):
        if len(frac) == 0:
            return (0, 1)
        elif len(frac) == 1:
            return (frac[0], 1)
        else:
            remainder = frac[1:len(frac)]
            (num, denom) = self.contfrac_to_rational(remainder)
            return (frac[0] * num + denom, num)

    def __init__(self, n, e):
        self.d = None
        self.p = None
        self.q = None
        sys.setrecursionlimit(100000)
        frac = self.rational_to_contfrac(e, n)
        convergents = self.convergents_from_contfrac(frac)

        for (k, d) in convergents:
            if k != 0 and (e * d - 1) % k == 0:
                phi = (e * d - 1) // k
                s = n - phi + 1
                discr = s * s - 4 * n
                if(discr >= 0):
                    if is_square(discr) and (s + isqrt(discr)) % 2 == 0:
                        self.d = d
                        x = Symbol('x')
                        roots = solve(x ** 2 - s * x + n, x)
                        if len(roots) == 2:
                            self.p = roots[0]
                            self.q = roots[1]
                        break
