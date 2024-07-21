import streamlit as st
import subprocess
import time
import os
import requests
import psutil
import sqlite3
import bcrypt
import pandas as pd
from datetime import datetime
from st_aggrid import AgGrid, GridOptionsBuilder
import pytz
from streamlit_cookies_manager import EncryptedCookieManager
from dotenv import load_dotenv

# Set page title
st.title("PDS Grader")

# Load environment variables from a .env file
load_dotenv('.env')

# Fetch the keys from environment variables
COOKIE_KEY = os.getenv('COOKIE_KEY')
COOKIE_PASSWORD = os.getenv('COOKIE_PASSWORD')

# Check if the COOKIE_KEY and COOKIE_PASSWORD meet the required criteria
if not COOKIE_KEY or len(COOKIE_KEY) != 64:
    st.error("The COOKIE_KEY must be a 64-character key in hexadecimal format.")
    st.stop()

if not COOKIE_PASSWORD:
    st.error("The COOKIE_PASSWORD must be set.")
    st.stop()

# Initialize the cookies manager
cookies = EncryptedCookieManager(
    prefix="myapp_",  # unique prefix to distinguish cookies used by this app
    password=COOKIE_PASSWORD  # password for encrypting cookies from environment variables
)

# Ensure cookies are loaded
if not cookies.ready():
    st.error("Failed to initialize encrypted cookies.")
    st.stop()

# Load login state from cookies
if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = cookies.get("logged_in") == "true"

if 'username' not in st.session_state:
    st.session_state['username'] = cookies.get("username", "")

# Initialize user database
def init_user_db():
    with sqlite3.connect('users.db') as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL
            )
        ''')
        conn.commit()

init_user_db()

# Function to check credentials
def check_credentials(username, password):
    username = username.lower()
    try:
        with sqlite3.connect('users.db') as conn:
            c = conn.cursor()
            c.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
            result = c.fetchone()
    except Exception as e:
        st.error(f"Error checking credentials: {e}")
        return False

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
        with sqlite3.connect('users.db') as conn:
            c = conn.cursor()
            c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password_hash.decode('utf-8')))
            conn.commit()
    except Exception as e:
        st.error(f"Error adding user: {e}")

# Check if the user already exists
def user_exists(username):
    username = username.lower()
    try:
        with sqlite3.connect('users.db') as conn:
            c = conn.cursor()
            c.execute('SELECT 1 FROM users WHERE username = ?', (username,))
            result = c.fetchone()
    except Exception as e:
        st.error(f"Error checking user existence: {e}")
        return False
    return result is not None

# Callback function to enforce lowercase
def to_lowercase(key):
    if key in st.session_state:
        st.session_state[key] = st.session_state[key].lower().replace(" ", "")

def compile_cpp(source_path, output_path):
    command = ["g++", "-std=c++17", source_path, "-o", output_path]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode, result.stdout.decode(), result.stderr.decode()

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
            except psutil.NoSuchProcess:
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
        return "", str(e), None, None, -1

def grade(output, expected_output_file, runtime, max_memory, runtime_limit, memory_limit):
    try:
        with open(expected_output_file, 'r') as f:
            expected_output = f.read()

        score_output = 1 if output.strip() == expected_output.strip() else 0
    except Exception as e:
        score_output = 0

    score_runtime = 1 if runtime <= runtime_limit else 0
    score_memory = 1 if max_memory <= memory_limit else 0

    return score_output, score_runtime, score_memory

def add_row(username, problem_choice, score, runtime, memory):
    try:
        conn = sqlite3.connect('submissions.db')
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS submissions (
                id INTEGER PRIMARY KEY,
                username TEXT,
                problem_choice TEXT,
                score TEXT,
                runtime TEXT,
                memory TEXT,
                timestamp TEXT
            )
        ''')
        conn.commit()

        timestamp = datetime.now(pytz.utc).strftime('%Y-%m-%d %H:%M:%S %Z')
        c.execute('''
            INSERT INTO submissions (username, problem_choice, score, runtime, memory, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (username, problem_choice, score, runtime, memory, timestamp))
        conn.commit()
    except Exception as e:
        st.error(f"Error adding submission: {e}")
    finally:
        conn.close()

def load_data():
    try:
        conn = sqlite3.connect('submissions.db')
        df = pd.read_sql_query('SELECT * FROM submissions', conn)
        return df
    except Exception as e:
        st.error(f"Error loading data: {e}")
        return pd.DataFrame()
    finally:
        conn.close()

# Handle logged-in state
if st.session_state['logged_in']:
    st.sidebar.write(f"# Welcome! {st.session_state['username']}")
    if st.sidebar.button("Logout"):
        st.session_state['logged_in'] = False
        st.session_state['username'] = ""
        cookies["logged_in"] = "false"
        cookies["username"] = ""
        cookies.save()
        st.experimental_rerun()
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
                cookies["logged_in"] = "true"
                cookies["username"] = username
                cookies.save()
                st.experimental_rerun()
            else:
                st.sidebar.warning("Incorrect Username/Password")

    elif choice == "Register":
        st.sidebar.subheader("Create New Account")
        new_username = st.sidebar.text_input("Username", key="register_username", on_change=to_lowercase, args=("register_username",))
        new_password = st.sidebar.text_input("Password", type="password", key="register_password")
        register_button = st.sidebar.button("Register")

        if register_button:
            if user_exists(new_username):
                st.sidebar.warning("Username already exists")
            else:
                add_user(new_username, new_password)
                st.sidebar.success("Account created successfully")

if st.session_state['logged_in']:
    problem_choice = st.selectbox("Select a problem", ["pointing", "stonks"])

    source_code = st.text_area("Enter your C/C++ code here")

    input_files = {
        "pointing": "problems/pointing/input.txt",
        "stonks": "problems/stonks/input.txt"
    }

    expected_output_files = {
        "pointing": "problems/pointing/expected_output.txt",
        "stonks": "problems/stonks/expected_output.txt"
    }

    runtime_limits = {
        "pointing": 1.0,
        "stonks": 1.0
    }

    memory_limits = {
        "pointing": 128 * 1024 * 1024,
        "stonks": 128 * 1024 * 1024
    }

    if st.button("Submit"):
        if not source_code:
            st.error("Please enter your source code.")
        else:
            try:
                problem_input_file = input_files[problem_choice]
                expected_output_file = expected_output_files[problem_choice]
                runtime_limit = runtime_limits[problem_choice]
                memory_limit = memory_limits[problem_choice]

                if not os.path.exists('submitted_code'):
                    os.makedirs('submitted_code')

                source_code_path = f"submitted_code/{st.session_state['username']}_{problem_choice}.cpp"
                with open(source_code_path, 'w') as f:
                    f.write(source_code)

                executable_path = f"submitted_code/{st.session_state['username']}_{problem_choice}.out"
                compile_returncode, compile_stdout, compile_stderr = compile_cpp(source_code_path, executable_path)

                if compile_returncode != 0:
                    st.error(f"Compilation failed with error: {compile_stderr}")
                else:
                    st.success("Compilation successful.")
                    stdout, stderr, runtime, max_memory, returncode = run_executable(executable_path, problem_input_file, runtime_limit, memory_limit)

                    if returncode == -1:
                        st.error("Execution timed out.")
                    elif returncode != 0:
                        st.error(f"Execution failed with error: {stderr}")
                    else:
                        score_output, score_runtime, score_memory = grade(stdout, expected_output_file, runtime, max_memory, runtime_limit, memory_limit)
                        total_score = score_output + score_runtime + score_memory

                        st.write(f"Output Score: {score_output} / 1")
                        st.write(f"Runtime Score: {score_runtime} / 1")
                        st.write(f"Memory Score: {score_memory} / 1")
                        st.write(f"Total Score: {total_score} / 3")

                        add_row(st.session_state['username'], problem_choice, total_score, runtime, max_memory)

            except Exception as e:
                st.error(f"An error occurred: {e}")

    if st.button("View Submissions"):
        df = load_data()
        if not df.empty:
            st.write("## Submissions")
            gb = GridOptionsBuilder.from_dataframe(df)
            gb.configure_pagination()
            grid_options = gb.build()
            AgGrid(df, gridOptions=grid_options)
        else:
            st.write("No submissions found.")