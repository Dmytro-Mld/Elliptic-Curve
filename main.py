class EllipticCurve:
    def __init__(self, a, b, p):
        self.a = a
        self.b = b
        self.p = p
        if (4 * a**3 + 27 * b**2) % p == 0:
            raise ValueError("Крива є виродженою")
        
class ECPoint:
    def __init__(self, curve, x, y, z):
        self.curve = curve
        self.x = x
        self.y = y
        self.z = z

    def PointExists(P, curve):
        y_pow_2 = (pow(P.x, 3, curve.p) + curve.a * P.x * pow(P.z, 2, curve.p) + curve.b * pow(P.z, 3, curve.p)) % curve.p # Y^2*Z = X^3 + aXZ^2 + bZ^3 mod p
        if (y_pow_2) == (pow(P.y, 2, curve.p) * (P.z % curve.p)):
            return "Point belongs to this curve"
        else:
            return "Point does not belong to this curve"

    def is_infinity(self):
        return self.x is None and self.y is None

    def __eq__(self, other):
        return (self.x, self.y, self.curve) == (other.x, other.y, other.curve)
    
    def __str__(self):
        if self.is_infinity():
            return "Point at Infinity"
        return f"({self.x}, {self.y})"
    

def main():
    curve = EllipticCurve(a = -0x3, b = 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1, p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF)
    P = ECPoint(curve, 3956612991426730881572690625539101191081173707988913134798, 734723113272013350779810590895915026169243248806908472640, 1)
    print(curve.p)
    print(ECPoint.PointExists(P, curve))

main()