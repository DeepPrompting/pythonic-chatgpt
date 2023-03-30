import functools
import logging
import os
import time

import openai
import yaml

# Reading YAML file
with open("config.yaml", "r") as f:
    config = yaml.load(f, Loader=yaml.FullLoader)
    globals().update(config)

api_call_times = 3.0
rate_limit = 20.0
safe_time = 60.0 / (rate_limit / api_call_times)


def openai_throttler(api_call_times=3.0, rate_limit=20.0):
    safe_time = 60.0 / (rate_limit / api_call_times)

    def decorator(func):
        last_called = [0.0]

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            elapsed_time = time.monotonic() - last_called[0]
            time_to_wait = safe_time - elapsed_time

            if time_to_wait > 0:
                time.sleep(time_to_wait)

            last_called[0] = time.monotonic()
            print(args)
            response = func(*args, **kwargs)

            return response

        return wrapper

    return decorator


# Set up the logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Set up the formatter
formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

# Set up the handler
handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
handler.setFormatter(formatter)

# Add the handler to the logger
logger.addHandler(handler)


def log_openai_calls(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        logger.info(f"Call OpenAI API request: {args} {kwargs}")
        response = func(*args, **kwargs)
        logger.info(f"Received OpenAI API response: {response}")
        return response

    return wrapper
