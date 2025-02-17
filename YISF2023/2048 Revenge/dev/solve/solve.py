import numpy as np
import copy
from pwn import*

N = 6
B = [2, 6, 2, 0, 0, 1, 9, 4, 2, 1, 0, 0, 3, 5, 3, 2, 9, 6, 6, 3, 4, 2, 7, 8, 0, 1, 3, 3, 7, 7, 0, 1, 9, 8, 3, 1]
B = list(map(lambda x : x*x, B))
C = [4170, 1752, 7576, 8131, 5112, 8096, 16104, 7061, 13860, 17980, 4755, 14877, 20727, 8451, 19733, 29389, 17124, 25329, 26635, 10210, 18349, 30123, 13720, 24617, 16024, 5873, 13277, 19728, 10782, 17628, 26894, 25512, 24341, 12939, 28739, 22839]
B = np.array(B).reshape(6,6)
C = np.array(C).reshape(6,6)

for i in range(N):
    for j in range(N):
        if i == j:
            for k in range(i):
                B[i][k], B[i][N - 1 - k] = B[i][N - 1 - k], B[i][k]

B_inv = np.linalg.inv(B)
res = np.dot(B_inv, C).round().flatten().astype(int).tolist()

# res = [193, 29, 28, 185, 31, 122, 68, 26, 183, 188, 117, 184, 194, 157, 188, 111, 188, 212, 146, 185, 136, 29, 187, 69, 175, 100, 22, 191, 155, 105, 174, 72, 124, 179, 24, 136]
print(res)