import gmpy2
import hashlib
import random
import time
from gmpy2 import mpz, invert, powmod

# SM2国密标准参数 (GB/T 32918.1-2016)
FIELD_PRIME = mpz('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF', 16)  # 有限域素数p
CURVE_PARAM_A = mpz('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC', 16)  # 曲线参数a
CURVE_PARAM_B = mpz('28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93', 16)  # 曲线参数b
GROUP_ORDER = mpz('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123', 16)  # 群阶n
BASE_POINT_X = mpz('32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7', 16)  # 基点G的x坐标
BASE_POINT_Y = mpz('BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0', 16)  # 基点G的y坐标


class JacobianPoint:
    """采用Jacobian投影坐标表示的椭圆曲线上的点"""

    def __init__(self, x, y, z=mpz(1)):
        self.x = x  # x坐标
        self.y = y  # y坐标
        self.z = z  # 投影坐标参数z

    def is_infinite(self):
        """判断是否为无穷远点（z=0）"""
        return self.z == 0

    def to_affine(self):
        """将Jacobian坐标转换为仿射坐标（x, y）"""
        if self.is_infinite():
            return (None, None)

        z_inverse = invert(self.z, FIELD_PRIME)
        z_squared_inverse = (z_inverse * z_inverse) % FIELD_PRIME
        x_affine = (self.x * z_squared_inverse) % FIELD_PRIME
        y_affine = (self.y * z_squared_inverse * z_inverse) % FIELD_PRIME

        return (x_affine, y_affine)


INFINITE_POINT = JacobianPoint(mpz(0), mpz(1), mpz(0))  # 无穷远点


def point_double_jacobian(p):
    """Jacobian坐标下的点加倍运算"""
    if p.is_infinite() or p.y == 0:
        return INFINITE_POINT

    x1, y1, z1 = p.x, p.y, p.z

    # 计算中间变量
    s = (4 * x1 * y1 * y1) % FIELD_PRIME
    m = (3 * x1 * x1 + CURVE_PARAM_A * powmod(z1, 4, FIELD_PRIME)) % FIELD_PRIME

    # 计算新点坐标
    x3 = (m * m - 2 * s) % FIELD_PRIME
    y3 = (m * (s - x3) - 8 * powmod(y1, 4, FIELD_PRIME)) % FIELD_PRIME
    z3 = (2 * y1 * z1) % FIELD_PRIME

    return JacobianPoint(x3, y3, z3)


def point_add_jacobian(p, q):
    """Jacobian坐标下的点加法运算"""
    if p.is_infinite():
        return q
    if q.is_infinite():
        return p

    x1, y1, z1 = p.x, p.y, p.z
    x2, y2, z2 = q.x, q.y, q.z

    # 计算中间变量
    z1_squared = powmod(z1, 2, FIELD_PRIME)
    z2_squared = powmod(z2, 2, FIELD_PRIME)
    u1 = (x1 * z2_squared) % FIELD_PRIME
    u2 = (x2 * z1_squared) % FIELD_PRIME
    s1 = (y1 * z2 * z2_squared) % FIELD_PRIME
    s2 = (y2 * z1 * z1_squared) % FIELD_PRIME

    # 处理特殊情况
    if u1 == u2:
        if s1 != s2:
            return INFINITE_POINT
        else:
            return point_double_jacobian(p)

    # 计算斜率相关变量
    h = (u2 - u1) % FIELD_PRIME
    r = (s2 - s1) % FIELD_PRIME
    h_squared = (h * h) % FIELD_PRIME
    h_cubed = (h * h_squared) % FIELD_PRIME
    v = (u1 * h_squared) % FIELD_PRIME

    # 计算新点坐标
    x3 = (r * r - h_cubed - 2 * v) % FIELD_PRIME
    y3 = (r * (v - x3) - s1 * h_cubed) % FIELD_PRIME
    z3 = (h * z1 * z2) % FIELD_PRIME

    return JacobianPoint(x3, y3, z3)


def scalar_multiply(k, p):
    """标量乘法：计算k*p（使用Jacobian坐标优化）"""
    result = INFINITE_POINT
    current = p

    while k > 0:
        if k & 1:
            result = point_add_jacobian(result, current)
        current = point_double_jacobian(current)
        k >>= 1  # 右移一位，处理下一个比特

    return result


def generate_key_pair():
    """生成SM2密钥对（私钥+公钥）"""
    # 生成随机私钥d（1 < d < n）
    rand_state = gmpy2.random_state(random.SystemRandom().randint(0, 2 ** 64))
    private_key = gmpy2.mpz_random(rand_state, GROUP_ORDER - 1) + 1

    # 计算公钥P = d*G
    base_point = JacobianPoint(BASE_POINT_X, BASE_POINT_Y)
    public_key_point = scalar_multiply(private_key, base_point)
    public_key_affine = public_key_point.to_affine()

    return private_key, public_key_affine


def sm3_hash(message):
    """SM3哈希函数（此处用SHA256模拟，实际应用需替换为标准SM3实现）"""
    return hashlib.sha256(message).digest()


def sm2_sign(message, private_key):
    """SM2签名算法实现"""
    # 计算消息哈希e
    e_hash = int.from_bytes(sm3_hash(message), 'big') % GROUP_ORDER
    base_point = JacobianPoint(BASE_POINT_X, BASE_POINT_Y)

    while True:
        # 生成随机数k
        rand_state = gmpy2.random_state(random.SystemRandom().randint(0, 2 ** 64))
        k = gmpy2.mpz_random(rand_state, GROUP_ORDER - 1) + 1

        # 计算k*G
        k_g_point = scalar_multiply(k, base_point)
        x1, _ = k_g_point.to_affine()

        # 计算r
        r = (e_hash + x1) % GROUP_ORDER

        # 检查r的有效性
        if r == 0 or (r + k) % GROUP_ORDER == 0:
            continue

        # 计算s
        s_numerator = (k - r * private_key) % GROUP_ORDER
        s = (invert(1 + private_key, GROUP_ORDER) * s_numerator) % GROUP_ORDER

        if s != 0:
            break

    return (int(r), int(s))


def sm2_verify(message, signature, public_key):
    """SM2验签算法实现"""
    r, s = signature

    # 验证r和s的范围有效性
    if not (1 <= r <= GROUP_ORDER - 1) or not (1 <= s <= GROUP_ORDER - 1):
        return False

    # 计算消息哈希e
    e_hash = int.from_bytes(sm3_hash(message), 'big') % GROUP_ORDER
    t = (r + s) % GROUP_ORDER

    if t == 0:
        return False

    # 计算验证点
    base_point = JacobianPoint(BASE_POINT_X, BASE_POINT_Y)
    public_key_point = JacobianPoint(mpz(public_key[0]), mpz(public_key[1]))

    s_g = scalar_multiply(s, base_point)
    t_p = scalar_multiply(t, public_key_point)
    verify_point = point_add_jacobian(s_g, t_p)

    # 计算验证结果
    x1, _ = verify_point.to_affine()
    verify_r = (e_hash + x1) % GROUP_ORDER

    return int(verify_r) == r


if __name__ == "__main__":
    # 生成密钥对
    private_key, public_key = generate_key_pair()
    print(f"私钥: 0x{private_key:064x}")
    print(f"公钥: (0x{public_key[0]:064x}, 0x{public_key[1]:064x})")

    # 测试消息
    test_message = b"SM2 Digital Signature with Jacobian Coordinates"

    # 测试签名效率
    signature_times = []
    test_rounds = 10
    for _ in range(test_rounds):
        start_time = time.perf_counter()
        signature = sm2_sign(test_message, private_key)
        end_time = time.perf_counter()
        signature_times.append(end_time - start_time)

    avg_sign_time = sum(signature_times) / test_rounds * 1000
    print(f"\n签名平均耗时: {avg_sign_time:.3f} ms")

    # 测试验签效率
    verify_times = []
    for _ in range(test_rounds):
        start_time = time.perf_counter()
        is_valid = sm2_verify(test_message, signature, public_key)
        end_time = time.perf_counter()
        verify_times.append(end_time - start_time)

    avg_verify_time = sum(verify_times) / test_rounds * 1000
    print(f"验签平均耗时: {avg_verify_time:.3f} ms")
    print(f"验签结果: {'有效' if is_valid else '无效'}")

