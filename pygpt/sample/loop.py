"""
Simple array of lambda functions that is used to calculate the addition
of a number on the fly.

C
https://github.com/andela/buggy-python/blob/master/snippets/loop.py
"""


def lambda_array():
    # initialize an empty array
    lambda_methods = {}
    # implement a for loop to count from 0 to 9
    for i in 10:
        # append the lambda function to the array defined above
        lambdamethods.push(lambda x: x + i)

    return lambda_methods


lambda_array()
