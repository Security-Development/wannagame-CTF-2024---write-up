import random

encrypted_flag_hex = "0203e2c0dd20182bea1d00f41b25ad314740c3b239a32755bab1b3ca1a98f0127f1a1aeefa15a418e9b03ad25b3a92a46c0f5a6f41cb580f7d8a3325c76e66b937baea"  # 예시: "b3a1f9c2..."

encrypted_flag = bytes.fromhex(encrypted_flag_hex)

flag_len = len(encrypted_flag)

# GET SEED
# for seed in range(0, 9000):
#     flag = list(encrypted_flag)[:3]
#     print("seed: c", seed)
#     random.seed(seed)
#     for _ in range(1337):
#         r = [random.randint(0, 255) for _ in range(flag_len)]
#         flag[0] ^= r[0]
#         flag[1] ^= r[1]
#         flag[2] ^= r[2]
#     if flag[0] == 87 and flag[1] == 49 and flag[2] == 123:
#         print("GET SEED!:", seed) # 3790
#         break

seed = 3790
random.seed(seed)
flag = list(encrypted_flag)

for _ in range(1337):
    flag = [x ^ y for x, y in zip(flag, [random.randint(0, 255) for _ in range(flag_len)])]

print(bytes(flag).decode("utf-8"))