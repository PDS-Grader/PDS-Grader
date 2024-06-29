import streamlit as st
import subprocess
import psutil
import time
import os

def compile_cpp(source_path, output_path):
    command = ["g++", source_path, "-o", output_path]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode, result.stdout.decode(), result.stderr.decode()

def run_executable(executable_path, input_data):
    try:
        start_time = time.time()
        process = subprocess.Popen([executable_path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        ps_process = psutil.Process(process.pid)
        stdout, stderr = process.communicate(input=input_data.encode(), timeout=5)
        end_time = time.time()
        runtime = end_time - start_time
        memory_info = ps_process.memory_info()
        max_memory = memory_info.rss
        return stdout.decode(), stderr.decode(), runtime, max_memory, process.returncode
    except subprocess.TimeoutExpired:
        process.kill()
        return "", "Error: Timeout", 5, None, -1
    except Exception as e:
        return "", f"Error: {str(e)}", 0, None, -1

def grade(output, expected_output, runtime, max_memory):
    correctness = 1 if output.strip() == expected_output.strip() else 0
    performance = 1 if runtime <= 1 and max_memory <= 50 * 1024 * 1024 else 0
    return correctness + performance

st.title("C++ Code Grader")

problems = {
    "Pointing": {
        "description": "./Problems/Pointing/Pointing.pdf",
        "test_cases": [
            {"input": "input for problem 1 - test case 1", "expected_output": "expected output for problem 1 - test case 1"},
            {"input": "input for problem 1 - test case 2", "expected_output": "expected output for problem 1 - test case 2"}
        ]
    },
    "Problem 2": {
        "description": "Problems/Problem 2/Problem 2.pdf",
        "test_cases": [
            {"input": "input for problem 2 - test case 1", "expected_output": "expected output for problem 2 - test case 1"},
            {"input": "input for problem 2 - test case 2", "expected_output": "expected output for problem 2 - test case 2"}
        ]
    }
    # Add more problems here
}

selected_problem = st.selectbox("Select a problem", list(problems.keys()))
description_path = f"./Problems/{selected_problem}/{selected_problem}.pdf"

st.write(f"### Description for {selected_problem}")
st.write(f"[Download Problem PDF]({description_path})")

uploaded_file = st.file_uploader("Upload your C++ file", type=["cpp"])

if uploaded_file is not None:
    source_code = uploaded_file.read()
    source_path = "submitted_code.cpp"
    executable_path = "./submitted_code"
    
    with open(source_path, "wb") as f:
        f.write(source_code)
    
    compile_returncode, comp
