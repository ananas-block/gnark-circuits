#!/usr/bin/env python3
"""Check the backwards curve identities over Q using only Python's stdlib."""
from fractions import Fraction
N=7
class P(dict):
    @staticmethod
    def value(v): return v if isinstance(v,P) else P({(0,)*N:Fraction(v)})
    def __add__(self,v):
        out=P(self)
        for m,c in P.value(v).items():
            out[m]=out.get(m,0)+c
            if not out[m]: del out[m]
        return out
    __radd__=__add__
    def __neg__(self): return P({m:-c for m,c in self.items()})
    def __sub__(self,v): return self+-P.value(v)
    def __rsub__(self,v): return P.value(v)+-self
    def __mul__(self,v):
        out=P()
        for ma,a in self.items():
            for mb,b in P.value(v).items():
                m=tuple(x+y for x,y in zip(ma,mb));out[m]=out.get(m,0)+a*b
                if not out[m]: del out[m]
        return out
    __rmul__=__mul__
    def __pow__(self,n):
        out=P.value(1)
        for _ in range(n):out=out*self
        return out

def var(i): return P({tuple(int(j==i) for j in range(N)):Fraction(1)})
x,y,l0,a,b,t,l=map(var,range(N))
def F(x,y): return y*y-x**3-a*x-b
xd=l0*l0-2*x;yd=l0*(x-xd)-y
assert not F(xd,yd)-F(x,y)-(xd-x)*(2*l0*y-3*x*x-a)
# Here x, y stand for D.x, D.y; substitute the two chord certificates.
xd,t,l,m,a,b,_=map(var,range(N))
e=l*l-2*xd-t;yd=m*e*Fraction(1,2);ty=l*(t-xd)+yd
q=t*t+t*xd+xd*xd+a-2*l*yd-l*l*(t-xd)
delta=m*(m+2*l);xo=t+delta;yo=(l+m)*(xo-xd)-yd
assert not F(xd,yd)-F(t,ty)-(t-xd)*q
assert not F(xo,yo)-F(t,ty)+delta*q
print('Three polynomial identities verified exactly over Q.')
