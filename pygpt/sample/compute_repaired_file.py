import math


def compute(num, times):
    result = num
    for i in range(times):
        try:
            result += math.exp(num)
            print(result)
        except OverflowError:
            print("Result is too large and cannot be handled")
            break
    return result


compute(1000, 2)
