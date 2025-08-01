Google_password_checkup.py：实现了Google password checkup的协议，该协议允许两方（P1 和 P2）在不透露各自完整集合内容的情况下，安全地计算它们共享元素的关联值之和。
主要类：
	1、ECGroup (椭圆曲线群)：模拟椭圆曲线群 G，提供哈希、幂运算和随机指数功能。（非本实验重点，不过多讲述）
	2、AHE (加法同态加密)：模拟一个支持加法同态操作的加密方案。（非本实验重点，不过多讲述）
	3、DDHPIS (DDH基私有交集和协议)：实现了协议的核心逻辑，包含P1和P2的各个轮次操作。
	其中主要函数：
		1）p1_round1(self, V, p2_pk): P1（第一方）的第一轮计算。生成P1的指数k1，计算并打乱H(v_i)^k1列表。
		2）p2_round2(self, W, Hvk1_from_p1): P2（第二方）的第二轮计算。生成P2的秘密指数k2和AHE密钥对；计算并打乱H(v_i)^k1k2列表（作为Z）；计算并打乱(H(w_j)^k2, AEnc(t_j))对列表。
		3）p1_round3(self, k1, Z_from_p2, p2_pairs_from_p2, p2_pk): P1的第三轮计算。计算H(w_j)^k1k2；基于Z列表识别交集元素；对交集元素的关联值密文进行同态求和；随机化最终密文。
		4）p2_output(self, sk, Enc_SJ_rand): P2的最终输出阶段。解密密文，得到交集元素的关联值之和。
