import argparse
import json
import os
import random
import time
from test import TestRunner

import code_completion
import yaml
from code_completion import CodeGeneration
from debug import Debug, DebugRunner
from prompting import enhance_prompt
from repair import Repair, RepairRunner
from static_analysis import StaticAnalysis, StaticAnalysisRunner
from util import logger

parser = argparse.ArgumentParser(description="Description of your program")

parser.add_argument("--root_folder", type=str, default=".", help="Root folder")
parser.add_argument(
    "--model_engine1",
    type=str,
    default="text-davinci-003",
    help="Model engine",
)
parser.add_argument(
    "--function_folder", type=str, default="example", help="Function folder"
)
parser.add_argument("--fuzz_prompt", action="store_true", help="Fuzz prompt")
parser.add_argument(
    "--prompt_path", type=str, default="prompt.txt", help="Prompts path"
)
parser.add_argument(
    "--repair_round",
    type=int,
    default=1,
    help="Number of rounds of error correction to attempt (default: 0)",
)
parser.add_argument(
    "--process",
    type=str,
    default="prompt",
    choices=["code", "prompt"],
    help="Type of input to process",
)
parser.add_argument("--code_path", type=str, help="Path to code file")

args = parser.parse_args()

# Access the argument values
root_folder = args.root_folder
model_engine1 = args.model_engine1
function_folder = args.function_folder
fuzz_prompt = args.fuzz_prompt
prompt_path = args.prompt_path
repair_round = args.repair_round

# Reading YAML file
with open("config.yaml", "r") as f:
    config = yaml.load(f, Loader=yaml.FullLoader)
    globals().update(config)

# Define the workflow
def code_analysis_and_repair_workflow():
    code_generation = CodeGeneration()

    # Process the input based on the options
    if args.process == "prompt":
        if args.prompt_path:
            # Read the prompt from the specified file path
            with open(args.prompt_path, "r") as f:
                prompt = f.read()
                # Generate code by the AGI model
                logger.info(
                    "--------------Generate code by the AGI model----------------------"
                )

                prompt = enhance_prompt(prompt)

                (
                    generated_code,
                    func_name,
                    func_name_short,
                ) = code_generation.generate_code(prompt)
        else:
            logger.info("Error: prompt file path not specified.")
    elif args.process == "code":
        if args.code_path:
            # Read the code from the specified file path
            with open(args.code_path, "r") as f:
                generated_code = f.read()
                func_name = code_generation.extract_function_signature(
                    code_string=generated_code
                )
                func_name_short = code_generation.extract_function_name(
                    func_name
                )

                with open(args.code_path, "r") as source_file:
                    with open(
                        "{}/{}/{}_init_test.py".format(
                            config["root_folder"],
                            config["function_folder"],
                            func_name_short,
                        ),
                        "w",
                    ) as destination_file:
                        destination_file.write(source_file.read())
                logger.info(
                    "extracted func name {} func name short {}".format(
                        func_name, func_name_short
                    )
                )
        else:
            logger.info("Error: code file path not specified.")
    else:
        logger.info("Error: process type not specified or invalid.")

    static_analysis = StaticAnalysisRunner()
    test = TestRunner()
    debug = DebugRunner()
    repair = RepairRunner()
    repair_round = config["repair_round"]
    repaired_code = ""

    while repair_round > 0:
        # Perform static analysis
        analysis_results = static_analysis.analyze(generated_code)

        # Run tests
        test_results = test.run_tests(generated_code, func_name_short)

        # Perform debug
        debug_results = debug.run_debug(
            generated_code, analysis_results, test_results
        )

        # Perform repairs
        repaired_code = repair.repair(
            generated_code, analysis_results, test_results, debug_results
        )
        logger.info("loop repaired code\n")
        logger.info(repaired_code)
        repair_round -= 1

    logger.info("-----------------final code result--------------------\n")
    logger.info(repaired_code)

    with open("sample/{}_repaired_file.py".format(func_name_short), "w") as f:
        f.write(repaired_code[0])

    namespace = {}
    logger.info(exec(repaired_code[0], namespace))
    return repaired_code


# python3 pygpt_runner.py --process prompt --prompt_path prompt.txt
if __name__ == "__main__":
    code_analysis_and_repair_workflow()
