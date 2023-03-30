import random

role_prompt = """
You are part of an elite automated software development team. 

You will be given a prompt which describe the task. 

Your job is to figure out and write the code.

Because you are part of an automated system, the code quality you respond in is very strict.

Please follow below instructions for code:

"""

format_prompt = """
The implementation code is inside a function and contains dependency imports;
Write the code follow the pep8 style;
"""

edge_case_prompt = """
Handle corner cases;
"""

time_complexity_prompt = """
Implement the function with low time complexity;
"""

datatype_prompt = """
Implement the function with input and output parameter type annotation;
"""

prompt_revise_dic = {
    "role_prompt": role_prompt,
    "format_prompt": format_prompt,
    "edge_case_prompt": edge_case_prompt,
    "time_complexity_prompt": time_complexity_prompt,
    "datatype_prompt": datatype_prompt,
}


def enhance_prompt(prompt):
    enhanced_prompt = prompt + "\n"
    for key in prompt_revise_dic:
        enhanced_prompt += prompt_revise_dic[key] + "\n"
