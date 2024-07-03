f = open("data.txt", "r")
try:
    print(f.read())
except:
    print("can't read")
