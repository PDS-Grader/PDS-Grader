import streamlit as st
import subprocess
import time
import os
import requests
import psutil
import sqlite3
import bcrypt

# Function to check credentials
def check_credentials(username, password):
    username = username.lower()
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
        result = c.fetchone()
    except Exception as e:
        st.error(f"Error checking credentials: {e}")
        return False
    finally:
        conn.close()

    if result:
        password_hash = result[0]
        if isinstance(password_hash, str):
            password_hash = password_hash.encode('utf-8')
        return bcrypt.checkpw(password.encode('utf-8'), password_hash)
    return False

# Function to add a new user
def add_user(username, password):
    username = username.lower()
    try:
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password_hash.decode('utf-8')))
        conn.commit()
    except Exception as e:
        st.error(f"Error adding user: {e}")
    finally:
        conn.close()

# Check if the user already exists
def user_exists(username):
    username = username.lower()
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT 1 FROM users WHERE username = ?', (username,))
        result = c.fetchone()
    except Exception as e:
        st.error(f"Error checking user existence: {e}")
        return False
    finally:
        conn.close()
    return result is not None

# Callback function to enforce lowercase
def to_lowercase(key):
    if key in st.session_state:
        st.session_state[key] = st.session_state[key].lower()

def compile_cpp(source_path, output_path):
    command = ["g++", "-std=c++17", source_path, "-o", output_path]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode, result.stdout.decode(), result.stderr.decode()

def download_file(url, destination):
    try:
        response = requests.get(url, headers={'Accept': 'application/vnd.github.v3.raw'})
        response.raise_for_status()
        with open(destination, 'wb') as f:
            f.write(response.content)
    except requests.exceptions.RequestException as e:
        st.error(f"Error downloading file from {url}: {str(e)}")

def run_executable(executable_path, input_file, runtime_limit, memory_limit):
    try:
        if not os.path.exists(input_file):
            st.error(f"Input file {input_file} does not exist.")
            return "", "Input file does not exist.", None, None, -1

        start_time = time.time()
        with open(input_file, 'r') as f:
            process = subprocess.Popen([executable_path], stdin=f, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            pid = process.pid

            # Retrieve memory usage before communicate
            try:
                process_info = psutil.Process(pid).memory_info()
                max_memory = process_info.rss
                # if max_memory == 0:
                #     max_memory = None  # Treat 0 memory as not available
            except psutil.NoSuchProcess:
                # max_memory = None  # Process might be terminated already
                max_memory = 0

            try:
                stdout, stderr = process.communicate(timeout=runtime_limit)
                returncode = process.returncode
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                returncode = -1

        end_time = time.time()
        runtime = end_time - start_time

        return stdout.decode(), stderr.decode(), runtime, max_memory, returncode

    except Exception as e:
        return "", f"Error: {str(e)}", 0, None, -1

def grade(output, expected_output_file, runtime, max_memory, runtime_limit, memory_limit):
    if runtime is None or max_memory is None:
        return 0, 0, 0 # Return 0 grade if runtime or max_memory is None
    
    with open(expected_output_file, 'r') as f:
        expected_output = f.read().strip()
    
    return 1 if output.strip() == expected_output.strip() else 0, 1 if runtime <= runtime_limit else 0, 1 if max_memory <= memory_limit else 0

st.title("PDS Grader")

def acc():   
    if 'logged_in' not in st.session_state:
        st.session_state['logged_in'] = False

    if 'username' not in st.session_state:
        st.session_state['username'] = ""

    if st.session_state['logged_in']:
        st.sidebar.write(f"# Welcome! {st.session_state['username']}")
        if st.sidebar.button("Logout"):
            st.session_state['logged_in'] = False
            st.session_state['username'] = ""
            st.experimental_rerun()
        # Add your main application logic here
    else:
        # Sidebar for navigation
        menu = ["Login", "Register"]
        choice = st.sidebar.radio("Menu", menu)

        if choice == "Login":
            st.sidebar.subheader("Login Section")

            username = st.sidebar.text_input("Username", key="login_username", on_change=to_lowercase, args=("login_username",))
            password = st.sidebar.text_input("Password", type="password", key="login_password")
            login_button = st.sidebar.button("Login")

            if login_button:
                if check_credentials(username, password):
                    st.session_state['logged_in'] = True
                    st.session_state['username'] = username
                    st.experimental_rerun()
                else:
                    st.sidebar.error("Invalid username or password")

        elif choice == "Register":
            st.sidebar.subheader("Create New Account")

            new_username = st.sidebar.text_input("New Username", key="register_username", on_change=to_lowercase, args=("register_username",))
            new_password = st.sidebar.text_input("New Password", type="password", key="register_password")
            register_button = st.sidebar.button("Register")

            if register_button:
                if user_exists(new_username):
                    st.sidebar.error("Username already exists. Please choose a different username.")
                else:
                    add_user(new_username, new_password)
                    st.sidebar.success("You have successfully created an account!")
                    st.sidebar.info("Go to the Login menu to log in.")
        
if __name__ == "__main__":
    acc()
            
# Grader

problems = {
    "Pointing": {
        "test_cases": 10,
        "rt": 1,  # Runtime limit in seconds
        "mem": 32 * 1024 * 1024  # Memory limit in bytes
    },
    "Stonks": {
        "test_cases": 10,
        "rt": 1,  # Runtime limit in seconds
        "mem": 32 * 1024 * 1024  # Memory limit in bytes
    }
    # Add more problems here
}

selected_problem = st.selectbox("Select a problem", list(problems.keys()))

st.write(f"### {selected_problem}")
with open(f"./Problems/{selected_problem}/{selected_problem}.pdf", "rb") as pdf:
    st.download_button("Download Problem", data=pdf.read(), file_name=f"{selected_problem}.pdf")

uploaded_file = st.file_uploader("Upload your code (.cpp file only)", type=["cpp"])

# Button to compile and run
if st.button("Submit Code"):
    if not st.session_state['logged_in']:
        st.error("Please login before submitting")
    elif uploaded_file is not None:
        source_code = uploaded_file.read()
        source_path = "submitted_code.cpp"
        executable_path = "./submitted_code"

        with open(source_path, "wb") as f:
            f.write(source_code)

        compile_returncode, compile_stdout, compile_stderr = compile_cpp(source_path, executable_path)

        # st.write(f"Compilation stdout:\n{compile_stdout}")
        # st.write(f"Compilation stderr:\n{compile_stderr}")

        if compile_returncode != 0:
            st.error(f"Compilation failed:\n{compile_stderr}")
        else:
            total_grade = 0
            total_test_cases = problems[selected_problem]["test_cases"]

            for idx in range(1, total_test_cases + 1):
                input_url = f"https://raw.githubusercontent.com/PakinDioxide/Grader_St/main/Problems/{selected_problem}/{idx}.in"
                input_file = f"./Problems/{selected_problem}/{idx}.in"
                # download_file(input_url, input_file)

                expected_output_url = f"https://raw.githubusercontent.com/PakinDioxide/Grader_St/main/Problems/{selected_problem}/{idx}.out"
                expected_output_file = f"Problems/{selected_problem}/{idx}.out"
                # download_file(expected_output_url, expected_output_file)

                output, errors, runtime, max_memory, returncode = run_executable(executable_path, input_file, problems[selected_problem]["rt"], problems[selected_problem]["mem"])

                opc, tle, mle = grade(output, expected_output_file, runtime, max_memory, problems[selected_problem]["rt"], problems[selected_problem]["mem"])
                total_grade += (opc and tle and mle)
                cw = "Correct Answer" if opc == 1 else "Wrong Answer"
                cw = "Time Limit Exceed" if tle == 0 else cw
                cw = "Memory Limit Exceed" if mle == 0 else cw
                st.write(f" Test Case {idx}\t: {cw} - {round(runtime * 1000)} ms - {round(max_memory / (1024 * 1024) * 1000)} kB")
                # st.write(f"Input File: {input_file}")
                # st.write(f"Expected Output File: {expected_output_file}")
                # st.write(f"Output: {output}")
                # st.write(f"Errors: {errors}")
                # st.write(f"Runtime: {runtime} seconds")
                # if max_memory is not None:
                #     st.write(f"Max Memory: {max_memory / (1024 * 1024)} Megabytes")  # Convert bytes to megabytes
                # else:
                #     st.write("Max Memory: N/A")
                # st.write(f"Return Code: {returncode}")
                # st.write(f"Grade: {grade_score}/1")
                # st.write("---")

            final_grade = total_grade * (100 / total_test_cases)
            st.write(f"### Total : {round(final_grade)}/{100}")

            # Clean up
            if os.path.exists(source_path):
                os.remove(source_path)
            if os.path.exists(executable_path):
                os.remove(executable_path)
    else:
        st.error("No file uploaded")

