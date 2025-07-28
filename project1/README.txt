sm4.cpp：实现SM4算法的基础软件版本。包含循环移位函数`rotl()`、加解密核心的合成变换`T()`、密钥扩展专用的合成变换`T_prime()`、密钥扩展函数`key_schedule()`及加解密主函数`sm4_crypt()`。正确性测试通过随机生成明文和密钥，对比加密后解密结果与原明文验证；效率测试通过大量重复加密同一明文（固定密钥），统计单次加密耗时。

T-table.cpp：基于基础版本，采用T-table查表法优化SM4。新增T表构造函数`init_tbox()`，将原`T`变换替换为查表函数`T_lookup()`。效率测试显示，查表优化能带来显著的性能提升。

simd.cpp：在T-table优化的基础上，通过SIMD技术实现并行加速。设计并行加密函数`sm4_encrypt4_sse()`，支持每轮同时处理4个数据块；通过`test_simd_correctness()`验证并行加密的正确性，通过`test_simd_performance()`测试并行模式下的效率，性能提升显著。

sm4gcm.cpp：实现基于SM4的GCM工作模式，集成加密、解密与认证功能。核心包括：`sm4_gcm_encrypt()`（对明文执行GCM加密，输出密文和认证标签）、`sm4_gcm_decrypt()`（解密密文并验证标签，返回认证结果）、`ctr_crypt()`（基于`sm4_crypt`的CTR模式加解密）及`GHASH`类（实现Galois域上的认证乘法与标签计算）。