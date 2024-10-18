import javaobj
import base64

# pip3 install javaobj-py3
with open(".cobaltstrike.beacon_keys", "rb") as f:
    key = javaobj.loads(f.read())

# 获取私钥和公钥的字节序列
priv = bytes(c & 0xFF for c in key.array.value.privateKey.encoded)
pub = bytes(c & 0xFF for c in key.array.value.publicKey.encoded)

# 将公钥进行 Base64 编码
encoded_pub = base64.b64encode(pub).decode()

print("-----BEGIN PUBLIC KEY-----")
# 将编码后的字符串每 64 个字符分成一行
formatted = '\n'.join(encoded_pub[i:i+64] for i in range(0, len(encoded_pub), 64))

# 打印格式化后的公钥
print(formatted)
print("-----END PUBLIC KEY-----")
