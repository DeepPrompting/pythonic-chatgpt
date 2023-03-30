import os
import test
import time

import openai
import yaml
from gen_fuzzcode import gen_fuzz_code
from util import logger

import pygpt

# Reading YAML file
with open("config.yaml", "r") as f:
    config = yaml.load(f, Loader=yaml.FullLoader)
    globals().update(config)


class TestRunner:
    def __init__(self):
        # Initialize the class
        self.testers = [FuzzTest(), OpenAITest()]
        # self.testers = [OpenAITest()]

    def run_tests(self, code, function_name_short):
        # Run tests on the code
        # Return the test results
        results = []
        for tester in self.testers:
            result = tester.run_tests(code, function_name_short)
            results.append(result)


class Test:
    def __init__(self):
        # Initialize the class
        return

    def run_tests(self, code, function_name_short):
        # Run tests on the code
        # Return the test results
        return


class FuzzTest(Test):
    def __init__(self):
        super().__init__()

    def run_tests(self, code, function_name_short):
        # Run tests on the code
        # Return the test results
        # Generate function input protobuf
        logger.info(
            "--------------Generate function input protobuf----------------------"
        )
        start = time.time()
        self.gen_func_input_protobuf(function_name_short)

        # Generate fuzz code
        logger.info("--------------Generate fuzz code----------------------")
        code_path = gen_fuzz_code(
            root_folder=root_folder,
            importname="{}_pb2".format(function_name_short),
            funcname=function_name_short,
            file1="{}_{}".format(
                function_name_short,
                config["model_engine1"].replace("-", "_"),
            ),
        )
        end = time.time()
        stable_time = float(end - start)

        logger.info(
            "one question exec time {} seconds without fuzzing".format(
                end - start
            )
        )
        # Run fuzz testing
        logger.info("--------------Run fuzz testing----------------------")
        # -jobs=8 MY_CORPUS/ seeds/
        cmd = "python3 -B {} -max_len=100 -max_total_time=10".format(code_path)
        logger.info("run cmd {}".format(cmd))
        stream = os.popen(cmd)
        output = stream.read()
        logger.info(output)
        end = time.time()
        logger.info("one question exec time {} seconds".format(end - start))
        pass

    def gen_func_input_protobuf(self, func_name="quick_sort"):
        # Set up the OpenAI API client
        openai.api_key = os.environ.get("OPENAI_API_KEY")
        model_engine = config["model_engine1"]

        # function quick_sort name and input param name constraint is very important
        py_file_name = "{}/{}/{}_{}.py".format(
            root_folder,
            config["function_folder"],
            func_name,
            model_engine.replace("-", "_"),
        )

        dir_path = root_folder + "/" + config["function_folder"]

        if not os.path.isdir(dir_path):
            os.mkdir(dir_path)

        with open(py_file_name, "r") as file:
            contents = file.read()
            # this is general than PA tools for different languages. The advantage is that
            # it can cross language use.
            prompt = "generate function input as protobuf format '{}', the msg name is {}Request".format(
                contents, func_name
            )

            # for model_engine in model_engine_list:
            # Generate a response
            completion = pygpt.create(
                engine=model_engine,
                prompt=prompt,
                max_tokens=1024,
                n=1,
                stop=None,
                temperature=0.5,
            )
            logger.info("call openai api finished")

            response = completion.choices[0].text
            logger.info(
                "model engine {} choices count {} ".format(
                    model_engine, len(completion.choices)
                )
            )
            logger.info(response)

            with open(
                "{}/{}/{}.proto".format(
                    root_folder, config["function_folder"], func_name
                ),
                "w",
            ) as f:
                header = 'syntax = "proto3";\n'
                f.write(header + response)
            classname = "{}Request".format(func_name)
            prompt = "generate function call use {} {}Request same name attribute as input {} in python;\n \
                The function param should has prefix '{}Request.' ".format(
                response, func_name, contents, func_name
            )
            logger.info(prompt)
            # for model_engine in model_engine_list:
            # Generate a response
            completion = pygpt.create(
                engine=model_engine,
                prompt=prompt,
                max_tokens=1024,
                n=1,
                stop=None,
                temperature=0.5,
            )
            logger.info("call openai api finished")

            response = completion.choices[0].text
            logger.info(response)

            with open(
                "{}/{}/{}_funccall.txt".format(
                    root_folder, config["function_folder"], func_name
                ),
                "w",
            ) as f:
                f.write(response)

            SRC_DIR = "./" + root_folder + "/" + config["function_folder"]
            DST_DIR = "./" + root_folder + "/" + config["function_folder"]

            cmd = "protoc -I={} --python_out={} {}/{}.proto".format(
                SRC_DIR, DST_DIR, SRC_DIR, func_name
            )

            logger.info("run cmd {}".format(cmd))
            stream = os.popen(cmd)
            output = stream.read()
            logger.info(output)


class OpenAITest(Test):
    def __init__(self):
        super().__init__()
        openai.api_key = os.environ.get("OPENAI_API_KEY")

    def generate_test_cases(self, prompt, function_name_short):
        # Use the OpenAI API to generate test cases based on the provided prompt
        response = pygpt.create(
            engine=config["model_engine1"],
            prompt=prompt,
            max_tokens=50,
            n=5,
            stop=None,
            temperature=0.5,
        )

        # Extract the generated test cases from the response
        test_cases = [choice.text.strip() for choice in response.choices]

        return test_cases

    def run_tests(self, code, function_name_short):
        # Generate test cases based on the code
        prompt = f"Test the following code:\n\n{code}\n\nWrite test cases to ensure it works correctly.\n\nTest case 1:"
        test_cases = self.generate_test_cases(prompt, function_name_short)

        # Run the tests and collect the results
        results = []
        for i, test_case in enumerate(test_cases):
            result = {}
            result["test_case"] = test_case
            code_with_assert = f"{code}\nassert {test_case}"
            try:
                # The exec() function is a built-in Python function that takes
                # a string containing Python code as input and executes that
                # code. In the context of this code, we're using exec()
                # to dynamically execute the user's code along with the test
                # case that we generated.

                exec(code_with_assert)
                result["result"] = "PASS"
            except Exception as e:
                result["result"] = "FAIL"
                result["message"] = f"Test case {i+1} failed: {test_case}"
                result["error_type"] = type(e).__name__
                result["error_raw_code"] = code_with_assert
            results.append(result)

        return results
