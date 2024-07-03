def add(a, b):
    c = 3
    return a + b + c
 
def subtract():
    """docs"""
    a = 1
    r = multiply(a)
    return a - r

def multiply(a, b=1):
    return a * b

def divide(a = 1, b = 2):
    return a / b
 
print(add(1, 2))
print(subtract())
print(multiply(1)) # 1,1
print(multiply(1, 2) )
print(divide(3, 4))
print(divide(3))  # 3, 2
print(divide()) # 1,2
