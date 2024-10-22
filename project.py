from ccakem import kem_keygen512, kem_encaps512, kem_decaps512

# 生成密钥对
priv, pub = kem_keygen512()

# 加密
secret1, cipher = kem_encaps512(pub)

# 解密
secret2 = kem_decaps512(priv, cipher)

# 验证共享密钥是否一致
if secret1 == secret2:
    print("共享密钥一致，算法正常工作。")
else:
    print("共享密钥不一致，可能存在漏洞。")


# 攻击1: 篡改密文
tampered_cipher = cipher[:-1] + [(cipher[-1] ^ 0xFF) % 256]
try:
    tampered_secret = kem_decaps512(priv, tampered_cipher)
    if tampered_secret == secret1:
        print("篡改密文后仍然成功解密，可能存在漏洞。")
    else:
        print("篡改密文后解密失败，算法正常工作。")
except Exception as e:
    print("篡改密文后解密失败，算法正常工作。")

# 攻击2: 使用错误的私钥解密
wrong_priv, _ = kem_keygen512()
try:
    if wrong_priv == priv:
        raise Exception("生成了相同的私钥")
    wrong_secret = kem_decaps512(wrong_priv, cipher)
    if wrong_secret == secret1:
        print("使用错误的私钥仍然成功解密，可能存在漏洞。")
    else:
        print("使用错误的私钥解密失败，算法正常工作。")
except Exception as e:
    print("使用错误的私钥解密失败，算法正常工作。")

# 攻击3: 重放攻击
try:
    replay_secret = kem_decaps512(priv, cipher)
    if replay_secret == secret2:
        print("重放攻击成功，算法正常工作。")
    else:
        print("重放攻击失败，可能存在漏洞。")
except Exception as e:
    print("重放攻击解密失败，算法正常工作。")

# 攻击4: 中间人攻击 - 篡改公钥
fake_pub = pub[:-1] + ([pub[-1] ^ 0xFF])
try:
    fake_secret, fake_cipher = kem_encaps512(fake_pub)
    intercepted_secret = kem_decaps512(priv, fake_cipher)
    if intercepted_secret == fake_secret:
        print("中间人攻击成功，可能存在漏洞。")
    else:
        print("中间人攻击失败，算法正常工作。")
except Exception as e:
    print("中间人攻击解密失败，算法正常工作。")