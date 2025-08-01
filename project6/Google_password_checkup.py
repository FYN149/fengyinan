import hashlib
import os
import random


class EllipticCurveGroup:
    """模拟椭圆曲线群 G，提供哈希映射、幂运算和随机指数生成功能"""

    def __init__(self, curve_name="prime256v1"):
        # 椭圆曲线群的阶（prime256v1的阶）
        self.order = 115792089237316195423570985008687907853269984665640564039457584007913129639937

    def generate_private_exponent(self):
        """生成群G中的随机私有指数（1到order-1之间）"""
        return random.randint(1, self.order - 1)

    def hash_to_group(self, identifier):
        """将标识符哈希后映射为群G的元素"""
        # 使用SHA-256哈希后转换为整数，再对群的阶取模
        hash_value = hashlib.sha256(identifier.encode()).hexdigest()
        return int(hash_value, 16) % self.order

    def exponentiate(self, base, exponent):
        """执行群G中的幂运算（base^exponent mod order）"""
        return pow(base, exponent, self.order)


class AdditiveHomomorphicEncryption:
    """模拟加法同态加密方案，支持加密、解密和同态加法"""

    def generate_keys(self, security_level=1024):
        """生成加法同态加密的公钥和私钥"""
        # 实际应用中应使用安全的密钥生成算法
        return "public_key", "private_key"

    def encrypt(self, public_key, value):
        """使用公钥加密明文值"""
        return f"encrypted({value})"

    def decrypt(self, private_key, ciphertext):
        """使用私钥解密密文"""
        if isinstance(ciphertext, str) and ciphertext.startswith("encrypted("):
            return int(ciphertext.split('(')[1][:-1])
        return 0

    def homomorphic_add(self, ciphertexts):
        """对多个密文执行同态加法"""
        total = 0
        for ct in ciphertexts:
            if isinstance(ct, str) and ct.startswith("encrypted("):
                total += int(ct.split('(')[1][:-1])
        return f"encrypted({total})"

    def randomize_ciphertext(self, public_key, ciphertext):
        """随机化密文以增强隐私性（添加随机噪声）"""
        return ciphertext


class DDHBasedPrivateIntersectionSum:
    """基于DDH假设的私有交集和协议实现"""

    def __init__(self):
        self.ec_group = EllipticCurveGroup()
        self.ahe = AdditiveHomomorphicEncryption()

    def party1_first_round(self, party1_elements, party2_public_key=None):
        """
        参与方P1的第一轮计算
        输入: P1的元素集合V
        输出: P1的私有指数k1和{H(v_i)^k1}列表
        """
        # 生成P1的私有指数k1
        private_exponent_p1 = self.ec_group.generate_private_exponent()

        # 计算每个元素v_i的哈希值并进行k1次幂运算
        transformed_elements = []
        for element in party1_elements:
            # 将元素映射到椭圆曲线群
            hashed_element = self.ec_group.hash_to_group(str(element))
            # 计算H(v_i)^k1
            transformed = self.ec_group.exponentiate(hashed_element, private_exponent_p1)
            transformed_elements.append(transformed)

        # 打乱顺序以保护隐私
        random.shuffle(transformed_elements)
        return private_exponent_p1, transformed_elements

    def party2_second_round(self, party2_elements_with_tags, p1_transformed_elements):
        """
        参与方P2的第二轮计算
        输入: P2的元素-标签对集合W和P1发送的{H(v_i)^k1}列表
        输出: P2的私有指数k2、AHE密钥对、Z列表和{(H(w_j)^k2, E(t_j))}列表
        """
        # 生成P2的私有指数k2
        private_exponent_p2 = self.ec_group.generate_private_exponent()

        # 生成加法同态加密的密钥对
        ahe_public_key, ahe_private_key = self.ahe.generate_keys()

        # 计算Z = {H(v_i)^(k1*k2)} 列表
        z_list = []
        for transformed in p1_transformed_elements:
            # 计算H(v_i)^(k1*k2) = (H(v_i)^k1)^k2
            z_element = self.ec_group.exponentiate(transformed, private_exponent_p2)
            z_list.append(z_element)

        # 打乱Z列表顺序
        random.shuffle(z_list)

        # 计算{(H(w_j)^k2, E(t_j))}列表
        p2_transformed_pairs = []
        for element, tag in party2_elements_with_tags:
            # 将元素映射到椭圆曲线群
            hashed_element = self.ec_group.hash_to_group(str(element))
            # 计算H(w_j)^k2
            transformed_element = self.ec_group.exponentiate(hashed_element, private_exponent_p2)
            # 加密标签t_j
            encrypted_tag = self.ahe.encrypt(ahe_public_key, tag)
            p2_transformed_pairs.append((transformed_element, encrypted_tag))

        # 打乱P2生成的列表顺序
        random.shuffle(p2_transformed_pairs)
        return private_exponent_p2, ahe_public_key, ahe_private_key, z_list, p2_transformed_pairs

    def party1_third_round(self, p1_private_exponent, p2_z_list, p2_transformed_pairs, p2_public_key):
        """
        参与方P1的第三轮计算
        输入: P1的私有指数k1、P2发送的Z列表和{(H(w_j)^k2, E(t_j))}列表
        输出: 交集标签和的加密结果（随机化后）
        """
        # 计算{H(w_j)^(k1*k2), E(t_j)}列表
        p1_processed_pairs = []
        for transformed_element, encrypted_tag in p2_transformed_pairs:
            # 计算H(w_j)^(k1*k2) = (H(w_j)^k2)^k1
            processed_element = self.ec_group.exponentiate(transformed_element, p1_private_exponent)
            p1_processed_pairs.append((processed_element, encrypted_tag))

        # 找出交集元素对应的加密标签
        intersection_ciphertexts = []
        for element, ciphertext in p1_processed_pairs:
            if element in p2_z_list:
                intersection_ciphertexts.append(ciphertext)

        # 对交集标签执行同态求和并随机化结果
        if intersection_ciphertexts:
            sum_ciphertext = self.ahe.homomorphic_add(intersection_ciphertexts)
            randomized_sum = self.ahe.randomize_ciphertext(p2_public_key, sum_ciphertext)
            return randomized_sum
        return None

    def party2_output_result(self, ahe_private_key, encrypted_sum):
        """
        参与方P2的结果计算
        输入: AHE私钥和P1发送的加密求和结果
        输出: 解密后的交集标签和
        """
        if encrypted_sum:
            return self.ahe.decrypt(ahe_private_key, encrypted_sum)
        return None
