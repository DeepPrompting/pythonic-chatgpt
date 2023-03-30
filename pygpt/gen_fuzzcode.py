import yaml
from util import logger

# Reading YAML file
with open("config.yaml", "r") as f:
    config = yaml.load(f, Loader=yaml.FullLoader)
    globals().update(config)


def gen_fuzz_code(
    root_folder="gen",
    importname="quick_sort_pb2",
    funcname="quick_sort",
    file1="quick_sort_code_cushman_001",
):
    classname = "{}Request".format(funcname)
    with open(
        "{}/{}/{}_funccall.txt".format(
            root_folder, config["function_folder"], funcname
        ),
        "r",
    ) as file:
        funcall = file.read().strip()

        code = f"""
import atheris
import atheris_libprotobuf_mutator
import sys
import os
from google.protobuf.json_format import MessageToJson

import {importname}

file_path = "{{}}/{{}}/{{}}".format("{config["root_folder"]}", "{funcname}", "{funcname}")
passed_test_cases_count = 0  
exception_count = 0
@atheris.instrument_func
def TestOneProtoInput({classname}):
    global passed_test_cases_count
    global exception_count
    with open(file_path + ".testcount", 'a') as f:
        f.write("passed_test_cases_count={{}};exception_count={{}}\\n".format(passed_test_cases_count, exception_count)) 
    
    try:
        first_data = None
        # Debugging purpose
        with open(file_path + ".testcase", 'a') as f:
            f.write(MessageToJson({classname})) 
            f.write("\\n")
        # msg will be an ExampleMessage as specified in the Setup() function below.
        
        try:
            import {file1}
            first_data = {file1}.{funcall}
        except Exception as e:
            with open(file_path + ".model1error", 'a') as f:
                f.write(str(e)) 
                f.write("\\n")

    except Exception as e:
        exception_count += 1
        with open("{{}}/{{}}/{{}}.error".format("{config["root_folder"]}", "{funcname}", "{funcname}"), 'w') as f:
            f.write(type(e).__name__)
            f.write(str(e))
        raise e
    if first_data != None:
        passed_test_cases_count += 1
    else:
        exception_count += 1

if __name__ == '__main__':
    try:
        if os.path.exists(file_path + ".testcase"):
            os.remove(file_path + ".testcase")
        if os.path.exists(file_path + ".output"):
            os.remove(file_path + ".output")   
        if os.path.exists(file_path + ".testcount"):
            os.remove(file_path + ".testcount")  
        for i in range(3):
            if os.path.exists(file_path + ".model{{}}error".format(i + 1)):
                os.remove(file_path + ".model{{}}error".format(i + 1)) 
        atheris_libprotobuf_mutator.Setup(
            sys.argv, TestOneProtoInput, proto={importname}.{classname})
        atheris.Fuzz()
    except Exception as e:
        with open(file_path + ".fuzzerror", 'w') as f:
            f.write(str(e)) 
            f.write("\\n")

    with open(file_path + ".success", 'w') as f:
        f.write("passed_test_cases_count={{}}".format(passed_test_cases_count)) 
        f.write("exception_count={{}}".format(exception_count)) 
        f.write("\\n")
        """

        logger.info(code)
        code_path = "{}/{}/{}_fuzz.py".format(
            root_folder, config["function_folder"], funcname
        )

        with open(code_path, "w") as f:
            f.write(code)

        return code_path
