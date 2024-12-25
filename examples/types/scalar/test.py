# empty string
_ = ""

# unicode
r = ""
s="\u210c"
t="1\u210c"
u="\u210c2"
print(s,t,u)

# bytes
a=b""
b=b"1"
c=b"sheesh"
d=b"\x00\x99\x33"
print(a, b, c, d)

# integer
z1 = 1152921504606846976
z2  = -1152921504606846976
z3 = 120
print(z1, z2, z3)

# float
x=0.0
y=1.5
print(x,y)

# None
e=None
f=None

# type
g=type(None)
h=type
i=int
j=bool
k=str

# bytearray
x1=bytearray()
x2 = bytearray(b'0123456789abcdef')  # https://github.com/python/cpython/issues/87090
x2[:10] = b'test'
print(x2)
