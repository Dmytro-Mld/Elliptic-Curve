import random
import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class EllipticCurve:
    def __init__(self, a, b, p, n):
        self.a = a
        self.b = b
        self.p = p
        self.n = n
        if (4 * a**3 + 27 * b**2) % p == 0:
            raise ValueError("Крива є виродженою")
        
class ECPoint:
    def __init__(self, curve, x, y, z):
        self.curve = curve
        self.x = x
        self.y = y
        self.z = z

    @classmethod
    def infinity(cls, curve):
        return cls(curve, 0, 1, 0) #creating a conctant infinity point

    def PointExists(P, curve):
        y_pow_2 = (pow(P.x, 3, curve.p) + curve.a * P.x * pow(P.z, 2, curve.p) + curve.b * pow(P.z, 3, curve.p)) % curve.p # Y^2*Z = X^3 + aXZ^2 + bZ^3 mod p
        if (y_pow_2) == (pow(P.y, 2, curve.p) * (P.z % curve.p)):
            return "Point belongs to this curve \n"
        else:
            return "Point does not belong to this curve \n"
        
    def PointDouble(P, curve):
        if (P.x == 0 and P.y == 1 and P.z == 0):
            return ECPoint.infinity(curve)
        elif (P.y == 0):                    #second order point
            return ECPoint.infinity(curve)
        
        a = curve.a
        p = curve.p

        W = a * pow(P.z, 2, p)
        W = (W + (3 * pow(P.x, 2, p))) % p
        S = (P.y * P.z) % p
        B = (P.x * P.y * S) % p
        H = (pow(W, 2, p) - (8 * B)) % p
        x1 = (2 * H * S) % p
        y1 = ((W * ((4 * B) - H)) - 8 * pow(P.y, 2, p) * pow(S, 2, p)) % p
        z1 = (8 * pow(S, 3, p)) % p

        P = ECPoint(curve, x1, y1, z1)
        return P
    
    def PointAdd(P1, P2, curve):
        if (P1.x == 0 and P1.y == 1 and P1.z == 0):
            return P2
        elif (P2.x == 0 and P2.y == 1 and P2.z == 0):
            return P1
        
        p = curve.p
        
        U1 = P2.y * P1.z % p
        U2 = P1.y * P2.z % p
        V1 = P2.x * P1.z % p
        V2 = P1.x * P2.z % p
        if V1 == V2:
            if U1 != U2: # тут додавання взаємо-обернених точок
                return ECPoint.infinity(curve)
            else: # тут вхідні точки однакові
                return ECPoint.PointDouble(P1, curve)
            
        U = (U1 - U2) % p
        V = (V1 - V2) % p
        W = (P1.z*P2.z)  % p
        A = ((pow(U, 2, p) * W) - pow(V, 3, p) - 2 * pow(V, 2, p) * V2) % p
        x3 = (V * A) % p
        y3 = (U*(pow(V, 2, p) * V2 - A) - pow(V, 3, p) * U2) % p
        z3 = (pow(V, 3, p) * W) % p
        P3 = ECPoint(curve, x3, y3, z3)
        return P3
            
    def ScalarMultiplicationMontgomery(P, k):
        R_inf = ECPoint.infinity(P.curve)
        #R1 = P
        R0 = P
        R1 = ECPoint.PointDouble(P, P.curve)
        curve = P.curve
        bits = bin(k)[2:]
        #for i in range(len(bits)-1, -1, -1):
        for i in range(1, len(bits)):
            if bits[i] == "0" :
                R1 = ECPoint.PointAdd(R0, R1, curve)
                R0 = ECPoint.PointDouble(R0, curve)
            else:
                R0 = ECPoint.PointAdd(R0, R1, curve)
                R1 = ECPoint.PointDouble(R1, curve)
        if R0.x == R_inf.x and R0.y == R_inf.y and R0.z == R_inf.z: 
            print("Calculations are correct!")
        return R0
    
    def ProjectiveToAffin(P):
        curve = P.curve
        p = curve.p
        if P.z == 0:
            return "Точка в точці на нескінченності, афінні координати не визначені"
        else:
            x_p = (P.x * pow(P.z, -1, p)) % p
            y_p = (P.y * pow(P.z, -1, p)) % p
        P_Afinn = ECPoint(curve, x_p, y_p, 1)
        return (P_Afinn)
    
    ########################################################################################################################

class DiffieHellmanKeys:
    def KeyExchange(G, n):
        d_a = random.randint(2, n)
        d_b = random.randint(2, n)
        Q_a = ECPoint.ScalarMultiplicationMontgomery(G, d_a)
        Q_b = ECPoint.ScalarMultiplicationMontgomery(G, d_b)
        
        S_a = ECPoint.ScalarMultiplicationMontgomery(Q_b, d_a)
        S_b = ECPoint.ScalarMultiplicationMontgomery(Q_a, d_b)
        S_a = ECPoint.ProjectiveToAffin(S_a)
        S_b = ECPoint.ProjectiveToAffin(S_b)
        Q_a = ECPoint.ProjectiveToAffin(Q_a)
        Q_b = ECPoint.ProjectiveToAffin(Q_b)

        if S_a.x == S_b.x and S_a.y == S_b.y: print("Secret was successfully chosen!!!")
        print("Q_a =", Q_a.x)
        print("Q_b =", Q_b.x)

        return S_a, Q_a, Q_b
    
    #Elliptic Curve Integrated Encryption Scheme

def xor_bytes(secret: bytes, key: bytes) -> bytes:
    key_len = len(key)
    secret = secret[-key_len:]  # беремо останні key_len байтів з секрету
    return bytes(s ^ k for s, k in zip(secret, key))

class KeyWrapper:
    @staticmethod
    def wrap(shared_secret: bytes, aes_key: bytes) -> bytes:
        return xor_bytes(shared_secret, aes_key)

    @staticmethod
    def unwrap(shared_secret: bytes, wrapped_key: bytes) -> bytes:
        return xor_bytes(shared_secret, wrapped_key)

class User:
    def __init__(self, curve, P, name = "User"):
        self.curve = curve
        self.name = name
        self.P = P
        self.__private_key_d = None
        self.public_key_Q = None
        self.Secret = None

    def GenerateKeys(self):
        P = self.P
        n = self.curve.n
        self.__private_key_d = random.randint(2, n)
        self.public_key_Q = ECPoint.ScalarMultiplicationMontgomery(P, self.__private_key_d)

    def GenerateSecret(self, Q):
        S = ECPoint.ScalarMultiplicationMontgomery(Q, self.__private_key_d)
        return S
            
    def get_public_key(self):
        return self.public_key_Q
    
class AESMessage:
    def __init__(self, ciphertext: bytes, nonce: bytes, tag: bytes):
        self.ciphertext = ciphertext
        self.nonce = nonce
        self.tag = tag

class AESHelper:
    def __init__(self, shared_secret: bytes):
        self.shared_secret = ECPoint.ProjectiveToAffin(shared_secret)


    def Enc(self, plaintext: bytes):
        S = int_to_bytes(self.shared_secret.x)
        aes_key  = get_random_bytes(16)
        cipher = AES.new(aes_key, AES.MODE_EAX)
        Cm, tag = cipher.encrypt_and_digest(plaintext)
        wrapped_key = KeyWrapper.wrap(S, aes_key)
        return AESMessage(Cm, cipher.nonce, tag), wrapped_key

    def Dec(self, aes_message: AESMessage, wrapped_key: bytes):
        S = int_to_bytes(self.shared_secret.x)
        aes_key = KeyWrapper.unwrap(S, wrapped_key)
        cipher = AES.new(aes_key, AES.MODE_EAX, nonce=aes_message.nonce)
        M = cipher.decrypt_and_verify(aes_message.ciphertext, aes_message.tag)
        return M

def bitstring_to_bytes(bit_str: str) -> bytes:

    if not bit_str:
        return b''
    
    num = int(bit_str, 2)

    num_bytes = (len(bit_str) + 7) // 8

    return num.to_bytes(num_bytes, byteorder='big')

def int_to_bytes(n: int) -> bytes:
    if n == 0:
        return b'\x00'
    num_bytes = (n.bit_length() + 7) // 8  # Округлення вгору до найближчого байта
    return n.to_bytes(num_bytes, byteorder='big')


def main():
    n = 6277101735386680763835789423176059013767194773182842284081
    curve = EllipticCurve(a = -0x3, b = 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1, p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF, n = n)
    k = 2
    G = ECPoint(curve, 602046282375688656758213480587526111916698976636884684818, 174050332293622031404857552280219410364023488927386650641, 1)
    P1 = ECPoint(curve, 931789767522875983662171506043830773045853946312191736306, 1005980030358638117964284564256122897803268444342190569730, 1)
    P2 = ECPoint(curve, 2072050170507445192066982344558550121838579746095343521127, 709252131592256521476556004551593188507842881677623059982  , 1)
    print(curve.p)
    print(ECPoint.PointExists(P1, curve))
    P_double = ECPoint.PointDouble(P1, curve)
    print(f"PointDouble(x={P_double.x}, y={P_double.y}, z={P_double.z})", "\n")
    P_add = ECPoint.PointAdd(P1, P2, curve)
    print(f"PointAdd(x={P_add.x}, y={P_add.y}, z={P_add.z})", "\n")
    P_scalar = ECPoint.ScalarMultiplicationMontgomery(P1, k)
    print(f"PointScalar(x={P_scalar.x}, y={P_scalar.y}, z={P_scalar.z})", "\n")
    P_scalar = ECPoint.ScalarMultiplicationMontgomery(P1, n)
    print(f"PointScalar_test(x={P_scalar.x}, y={P_scalar.y}, z={P_scalar.z})", "\n")
    P_affin = ECPoint.ProjectiveToAffin(P_double)
    print("Affine coordinates are: \nx =", P_affin.x,"\ny =", P_affin.y, "\n")



    ################################################################################################################
    print("DIFFIE HELLMAN KEY EXCHANGE")
    start = time.time()
    S, Q_a, Q_b = DiffieHellmanKeys.KeyExchange(G, n)
    end = time.time()
    print("Time:", end - start, "seconds\n")



    print("ELLIPTIC CURVE INTEGRATED ENCRYPTION SCHEME\n")
    alice = User(curve, G, name = "Alice")
    bob = User(curve, G, name = "Bob")
    #Bob publishing public key Q_b and curve parameters:
    print("Bob announces Elliptic curve parameters and his public key Q_b:\n")
    print(f"Elliptic Curve P-192\na = {curve.a}\nb = {curve.b}\nn = {n}\nP = {G.x, G.y, G.z}")
    User.GenerateKeys(bob)
    Q_b = User.get_public_key(bob)
    Q_b_aff = ECPoint.ProjectiveToAffin(Q_b)
    print(f"Q: x = {Q_b_aff.x}, y = {Q_b_aff.y}\n")

    
    M = "With great power comes great responsibility"
    print("The message Alice wants to send Bob:\n*This message should only be visible for testing purposes*")
    print(f"Message is: \"{M}\"\n")
    print("Alica ecrypts the message and sends envelope to Bob:")
    M_bin = ''.join(format(ord(i), '08b') for i in M)
    User.GenerateKeys(alice)
    Q_a = User.get_public_key(alice)
    alice_aes = AESHelper(User.GenerateSecret(alice, Q_b)) 
    aes_message, wrapped_key = alice_aes.Enc(bitstring_to_bytes(M_bin)) #Alice encrypts her message, wrapps the key, send it to Bob
    print(f"Alice's envelope to Bob (in bytes): \nciphertext = {aes_message.ciphertext}\nnonce = {aes_message.nonce}\ntag = {aes_message.tag}\nwraped key = {wrapped_key}\n")

    bob_aes = AESHelper(User.GenerateSecret(bob, Q_a))
    plaintext = bob_aes.Dec(aes_message, wrapped_key) #Bob decrypts the message
    print("Bob decrypts the message and shows us what Alice sent him:")
    print(plaintext.decode('utf-8'))

main()