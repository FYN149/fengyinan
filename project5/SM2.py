import hashlib
import random
import time

# SM2国密标准参数（GB/T 32918.1-2016）
FIELD_PRIME = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF  # 有限域素数p
CURVE_A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC          # 曲线参数a
CURVE_B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93          # 曲线参数b
GROUP_ORDER = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123       # 群阶n
BASE_X = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7            # 基点G的x坐标
BASE_Y = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0            # 基点G的y坐标


class ECCPoint:
    """椭圆曲线上的点"""
    def __init__(self, x, y):
        self.x = x  # x坐标
        self.y = y  # y坐标

    def is_infinite(self):
        """判断是否为无穷远点"""
        return self.x is None and self.y is None

    def __eq__(self, other):
        """点相等判断"""
        return self.x == other.x and self.y == other.y


INFINITE_POINT = ECCPoint(None, None)  # 无穷远点


def modular_inverse(x, mod=FIELD_PRIME):
    """计算模逆（x^-1 mod mod）"""
    if x == 0:
        raise ZeroDivisionError("除数不能为0")
    low_mult, high_mult = 1, 0
    low, high = x % mod, mod

    while low > 1:
        quotient = high // low
        new_mult = high_mult - low_mult * quotient
        new_val = high - low * quotient
        low_mult, low, high_mult, high = new_mult, new_val, low_mult, low

    return low_mult % mod


def point_addition(p, q):
    """椭圆曲线点加法"""
    if p.is_infinite():
        return q
    if q.is_infinite():
        return p
    if p.x == q.x and (p.y != q.y or p.y == 0):
        return INFINITE_POINT

    # 计算斜率
    if p == q:
        # 点加倍
        slope = (3 * p.x * p.x + CURVE_A) * modular_inverse(2 * p.y) % FIELD_PRIME
    else:
        # 不同点加法
        slope = (q.y - p.y) * modular_inverse(q.x - p.x) % FIELD_PRIME

    # 计算新点坐标
    x3 = (slope * slope - p.x - q.x) % FIELD_PRIME
    y3 = (slope * (p.x - x3) - p.y) % FIELD_PRIME
    return ECCPoint(x3, y3)


def point_scalar_mult(k, p):
    """椭圆曲线点 scalar 乘法（k*p）"""
    result = INFINITE_POINT
    current = p

    while k > 0:
        if k & 1:
            result = point_addition(result, current)
        current = point_addition(current, current)  # 加倍
        k >>= 1  # 右移一位
    return result


def generate_key_pair():
    """生成SM2密钥对（私钥+公钥）"""
    private_key = random.randrange(1, GROUP_ORDER)  # 私钥d
    public_key = point_scalar_mult(private_key, ECCPoint(BASE_X, BASE_Y))  # 公钥P = d*G
    return private_key, public_key


def sm3_hash(message):
    """SM3哈希（此处用SHA256模拟，实际应使用标准SM3实现）"""
    return hashlib.sha256(message).digest()


def sm2_sign(message, private_key):
    """SM2签名算法"""
    e_hash = int.from_bytes(sm3_hash(message), 'big')  # 消息哈希值e

    while True:
        k = random.randrange(1, GROUP_ORDER)  # 随机数k
        k_g = point_scalar_mult(k, ECCPoint(BASE_X, BASE_Y))  # k*G
        r = (e_hash + k_g.x) % GROUP_ORDER  # 计算r

        # 检查r的有效性
        if r == 0 or (r + k) % GROUP_ORDER == 0:
            continue

        # 计算s
        s = (modular_inverse(1 + private_key, GROUP_ORDER) * (k - r * private_key)) % GROUP_ORDER
        if s != 0:
            break

    return (r, s)


def sm2_verify(message, signature, public_key):
    """SM2验签算法"""
    r, s = signature

    # 验证r和s的范围
    if not (1 <= r <= GROUP_ORDER - 1) or not (1 <= s <= GROUP_ORDER - 1):
        return False

    e_hash = int.from_bytes(sm3_hash(message), 'big')  # 消息哈希值e
    t = (r + s) % GROUP_ORDER

    if t == 0:
        return False

    # 计算验证点
    s_g = point_scalar_mult(s, ECCPoint(BASE_X, BASE_Y))
    t_p = point_scalar_mult(t, public_key)
    verify_point = point_addition(s_g, t_p)

    # 计算验证值R
    verify_r = (e_hash + verify_point.x) % GROUP_ORDER
    return verify_r == r


if __name__ == "__main__":
    # 生成密钥对
    priv_key, pub_key = generate_key_pair()
    print(f"私钥: 0x{priv_key:064x}")
    print(f"公钥: (0x{pub_key.x:064x}, 0x{pub_key.y:064x})")

    # 测试消息
    test_msg = b"Hello SM2 Digital Signature"

    # 测试签名效率
    sign_times = []
    test_rounds = 10
    for _ in range(test_rounds):
        start = time.time()
        sig = sm2_sign(test_msg, priv_key)
        end = time.time()
        sign_times.append(end - start)
    avg_sign = sum(sign_times) / test_rounds * 1000
    print(f"\n签名平均耗时: {avg_sign:.3f} ms")

    # 测试验签效率
    verify_times = []
    for _ in range(test_rounds):
        start = time.time()
        is_valid = sm2_verify(test_msg, sig, pub_key)
        end = time.time()
        verify_times.append(end - start)
    avg_verify = sum(verify_times) / test_rounds * 1000
    print(f"验签平均耗时: {avg_verify:.3f} ms")
    print(f"验签结果: {'有效' if is_valid else '无效'}")
