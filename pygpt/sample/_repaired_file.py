import math
import sys


def compute(num, times):
    result = num
    for i in range(times):
        result += math.exp(num)
        if result > sys.maxsize:
            raise OverflowError(
                "Result exceeds maximum value that can be stored in a variable"
            )
        print(result)

    return result


compute(1000, 2)
