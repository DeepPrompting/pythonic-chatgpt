import os
import sys

import atheris
import atheris_libprotobuf_mutator
import compute_pb2
from google.protobuf.json_format import MessageToJson

file_path = "{}/{}/{}".format(".", "compute", "compute")
passed_test_cases_count = 0
exception_count = 0


@atheris.instrument_func
def TestOneProtoInput(computeRequest):
    global passed_test_cases_count
    global exception_count
    with open(file_path + ".testcount", "a") as f:
        f.write(
            "passed_test_cases_count={};exception_count={}\n".format(
                passed_test_cases_count, exception_count
            )
        )

    try:
        first_data = None
        # Debugging purpose
        with open(file_path + ".testcase", "a") as f:
            f.write(MessageToJson(computeRequest))
            f.write("\n")
        # msg will be an ExampleMessage as specified in the Setup() function below.

        try:
            import compute_init_test

            first_data = compute_init_test.compute(
                computeRequest.num, computeRequest.times
            )
        except Exception as e:
            with open(file_path + ".model1error", "a") as f:
                f.write(str(e))
                f.write("\n")

    except Exception as e:
        exception_count += 1
        with open(
            "{}/{}/{}.error".format(".", "compute", "compute"), "w"
        ) as f:
            f.write(type(e).__name__)
            f.write(str(e))
        raise e
    if first_data != None:
        passed_test_cases_count += 1
    else:
        exception_count += 1


if __name__ == "__main__":
    try:
        if os.path.exists(file_path + ".testcase"):
            os.remove(file_path + ".testcase")
        if os.path.exists(file_path + ".output"):
            os.remove(file_path + ".output")
        if os.path.exists(file_path + ".testcount"):
            os.remove(file_path + ".testcount")
        for i in range(3):
            if os.path.exists(file_path + ".model{}error".format(i + 1)):
                os.remove(file_path + ".model{}error".format(i + 1))
        atheris_libprotobuf_mutator.Setup(
            sys.argv, TestOneProtoInput, proto=compute_pb2.computeRequest
        )
        atheris.Fuzz()
    except Exception as e:
        with open(file_path + ".fuzzerror", "w") as f:
            f.write(str(e))
            f.write("\n")

    with open(file_path + ".success", "w") as f:
        f.write("passed_test_cases_count={}".format(passed_test_cases_count))
        f.write("exception_count={}".format(exception_count))
        f.write("\n")
