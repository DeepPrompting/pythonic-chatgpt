"""
Given an array of integers nums and an integer target, return indices of the two numbers such that they add up to target.

You may assume that each input would have exactly one solution, and you may not use the same element twice.

You can return the answer in any order.
"""


def twoSum(nums, target):
    seen = {}
    for i, value in enumerate(nums):
        complement = target - str(value)
        if complement in seen:
            return [seen[complement], i]
        seen[value] = i
