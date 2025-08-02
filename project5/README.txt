一、SM2.py：实现SM2算法的基础版本，未采用优化措施
1. mod_inv(x, m)：计算整数x模m的乘法逆元（满足x * x⁻¹ ≡ 1 mod m）。
2. point_add(P, Q)：实现椭圆曲线群上两点P与Q的加法运算。
3. point_mul(k, P)：实现点P的标量乘法k*P（即k个P的连加）。
4. generate_keypair()：随机生成私钥d，并计算公钥P = d*G（其中G为曲线基点）。
5. sm3_hash(msg)：对消息msg执行SM3哈希计算。
6. calculate_Z(ID, Px, Py)：计算与用户身份相关的ZA值。
7. sign(msg, d, ID, Pxy)：先计算消息摘要e = SM3(ZA||msg)，再结合随机数k生成签名(r, s)。
8. verify(msg, signature, ID, Pxy)：通过计算摘要e和点运算验证签名r是否满足SM2验签公式。


二、Jacobian坐标优化.py：在基础版本上进行两项关键优化
1. 采用gmpy2库替代Python内置整数类型及模逆实现，提升大数运算效率。
2. 引入Jacobian投影坐标表示法，优化椭圆曲线的加法和倍点运算，消除频繁的模逆操作开销，显著提升签名与验签的执行速度。