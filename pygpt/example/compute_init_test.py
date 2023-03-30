# OverflowError, it is difficult for chatgpt to directly repair
import math


def compute(num, times):
    result = num
    for i in range(times):
        result += math.exp(num)
        print(result)

    return result


compute(1000, 2)
