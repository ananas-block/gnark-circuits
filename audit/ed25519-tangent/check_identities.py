"""Exact algebra for the Ed25519 residual argument; requires sympy 1.14.0."""
import sympy as s

x, y, u, v, lam, mu, a, b = s.symbols('x y u v lambda mu a b')
F = lambda X, Y: Y**2-X**3-a*X-b
z = lam**2-x-u
w = u+mu*(mu+2*lam)
r = (lam+mu)*(w-x)-y
K = (z-x)*(u-x+lam*mu)-3*x*x-a
# Eliminate the two slope constraints using only division by the constant 2.
subs = {y: mu*(z-x)/2, v: mu*(z-x)/2+lam*(u-x)}
identities = {
    'table residual': F(u,v)-F(x,y)-(u-x)*K,
    'output residual': F(w,r)-F(x,y)-(w-x)*K,
    'terminal residual': F(w,r)-F(u,v)-(w-u)*K,
    'output x guard': w-u-mu*(mu+2*lam),
    'coincident tangent': K.subs(u,x)-(2*lam*y-3*x*x-a),
}
for name, expr in identities.items():
    if name == 'coincident tangent':
        expr = expr.subs(y,mu*(lam**2-3*x)/2)
    else:
        expr = expr.subs(subs, simultaneous=True)
    assert s.expand(expr) == 0, name
    print(name+': exact polynomial identity')
X, Y, alpha = s.symbols('X Y alpha')
dx = alpha**2-2*X
dy = alpha*(X-dx)-Y
assert s.expand((F(dx,dy)-F(X,Y)).subs(a,2*alpha*Y-3*X**2)) == 0
print('doubling residual: exact polynomial identity')

# Actual signed limb intervals and native carry bounds.
p = 2**255-19
q = 21888242871839275222246405745257275088548364400416034343698204186575808495617
widths = [43]*5+[40]
offset = sum(2**(width-1) * 2**(43*i) for i,width in enumerate(widths))
maximum = max(offset,2**255-1-offset)
B=2**129
assert maximum < p
assert 3*maximum < 2*p
assert 3*p < 8*q
assert 32*B < q and 32*2**126 < q
# Once z=1, k is exactly -1,0,1 in Fq. Both carry equations then lift.
low_max=sum(2**(widths[i]-1)*2**(43*i) for i in range(3))*3
high_max=sum(2**(widths[i]-1)*2**(43*(i-3)) for i in range(3,6))*3
assert low_max+(p%B)+8*(q%B)+16*B < q
assert high_max+(p//B)+8*(q//B)+16 < q
print('balanced slopes and native carry lifts: exact integer inequalities hold')
# Nonsingularity of the shifted Montgomery model.
off = 486662*pow(3,-1,p)%p
A=(1-486662*off)%p
Bcurve=(2*pow(off,3,p)-off)%p
assert (4*pow(A,3,p)+27*pow(Bcurve,2,p))%p != 0
print('curve discriminant: nonzero')
