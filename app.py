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

conn = sqlite3.connect('users.db')
c = conn.cursor()

c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL
    )
''')
conn.commit()

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
    cookies.initialize()
    st.stop()

# Load login state from cookies
if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = cookies.get("logged_in") == "true"

if 'username' not in st.session_state:
    st.session_state['username'] = cookies.get("username", "")

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

# Initialize SQLite database for submissions
conn = sqlite3.connect('submissions.db')
c = conn.cursor()

# Create table if it doesn't exist
c.execute('''
    CREATE TABLE IF NOT EXISTS data (
        DateTime TEXT,
        Name TEXT,
        Problem TEXT,
        Score TEXT,
        Runtime TEXT,
        Memory TEXT
    )
''')
conn.commit()

# Load data from the database into a DataFrame
def load_data():
    try:
        conn = sqlite3.connect('submissions.db')
        query = 'SELECT * FROM data ORDER BY DateTime DESC'
        df = pd.read_sql_query(query, conn)
        return df
    except Exception as e:
        st.error(f"Error loading data from database: {e}")
        return pd.DataFrame()  # Return an empty DataFrame on error
    finally:
        conn.close()

# Add a new row to the database
def add_row(name, problem, score, runtime, memory):
    timezone = pytz.timezone('Asia/Bangkok')
    datetime_now = datetime.now(timezone).strftime('%Y-%m-%d %H:%M:%S')
    with sqlite3.connect('submissions.db') as conn:
        c = conn.cursor()
        c.execute('''
            INSERT INTO data (DateTime, Name, Problem, Score, Runtime, Memory)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (datetime_now, name, problem, score, runtime, memory))
        conn.commit()

# Main application logic
st.title("PDS Grader")

# Session state initialization and management
if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False

if 'username' not in st.session_state:
    st.session_state['username'] = ""

# Handle login/logout actions
if st.session_state['logged_in']:
    st.sidebar.write(f"# Welcome! {st.session_state['username']}")
    if st.sidebar.button("Logout"):
        st.session_state['logged_in'] = False
        st.session_state['username'] = ""
        try:
            cookies.delete("logged_in")
            cookies.delete("username")
            cookies.save()
        except Exception as e:
            st.error(f"Error during logout: {e}")
        st.rerun()
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
                try:
                    cookies.set("logged_in", "true")
                    cookies.set("username", username)
                    cookies.save()
                except Exception as e:
                    st.error(f"Error setting cookies: {e}")
                st.rerun()
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
                
# Problem definitions
problems = {
    "Submissions": {
        
    },
    "Pointing": {
        "test_cases": 10,
        "rt": 1,  # Runtime limit in seconds
        "mem": 32 * 1024 * 1024  # Memory limit in bytes
    },
    "Stonks": {
        "test_cases": 10,
        "rt": 1,  # Runtime limit in seconds
        "mem": 32 * 1024 * 1024  # Memory limit in bytes
    },
    "Polygon": {
        "test_cases": 10,
        "rt": 1,  # Runtime limit in seconds
        "mem": 32 * 1024 * 1024  # Memory limit in bytes
    }
    # Add more problems here
}

# Select problem
selected_problem = st.selectbox("Select a problem or view submissions", list(problems.keys()))

st.write(f"### {selected_problem}")

# Load data for submissions or show problem PDF
if selected_problem == "Submissions":
    data = load_data()

    # Configure the AgGrid table
    gb = GridOptionsBuilder.from_dataframe(data)
    gb.configure_pagination(enabled=True)
    gb.configure_side_bar()
    gb.configure_default_column(editable=True, groupable=True)
    grid_options = gb.build()

    # Display the table with AgGrid
    AgGrid(data, gridOptions=grid_options)  
    
else:
    # Show problem PDF and allow file upload
    with open(f"./Problems/{selected_problem}/{selected_problem}.pdf", "rb") as pdf:
        st.download_button("Download Problem", data=pdf.read(), file_name=f"{selected_problem}.pdf")

    # File uploader for code submission
    uploaded_file = st.file_uploader("Upload code file (.cpp)", type=["cpp"])

    # Text area to input the code
    code = st.text_area("Or enter your code here", height=300)

    # Button to compile and run
    if st.button("Submit Code"):
        if not st.session_state['logged_in']:
            st.error("Please login before submitting")
        elif uploaded_file is not None:
            # Save the uploaded file
            source_path = "uploaded_code.cpp"
            with open(source_path, "wb") as f:
                f.write(uploaded_file.getvalue())

            executable_path = "./submitted_code"

            compile_returncode, compile_stdout, compile_stderr = compile_cpp(source_path, executable_path)

            if compile_returncode != 0:
                st.error(f"Compilation failed:\n{compile_stderr}")
            else:
                total_grade = 0
                total_test_cases = problems[selected_problem]["test_cases"]
                mxrt = 0
                mxmem = 0

                for idx in range(1, total_test_cases + 1):
                    input_url = f"https://raw.githubusercontent.com/Nagornph/Grader_St/main/Problems/{selected_problem}/{idx}.in"
                    input_file = f"./Problems/{selected_problem}/{idx}.in"
                    # download_file(input_url, input_file)

                    expected_output_url = f"https://raw.githubusercontent.com/NagornPh/Grader_St/main/Problems/{selected_problem}/{idx}.out"
                    expected_output_file = f"Problems/{selected_problem}/{idx}.out"
                    # download_file(expected_output_url, expected_output_file)

                    output, errors, runtime, max_memory, returncode = run_executable(executable_path, input_file, problems[selected_problem]["rt"], problems[selected_problem]["mem"])
                    mxrt = max(mxrt, runtime)
                    mxmem = max(mxmem, max_memory)
                    opc, tle, mle = grade(output, expected_output_file, runtime, max_memory, problems[selected_problem]["rt"], problems[selected_problem]["mem"])
                    total_grade += (opc and tle and mle)
                    cw = "Correct Answer" if opc == 1 else "Wrong Answer"
                    cw = "Time Limit Exceed" if tle == 0 else cw
                    cw = "Memory Limit Exceed" if mle == 0 else cw
                    st.write(f" Test Case {idx}\t: {cw} - {round(runtime * 1000)} ms - {round(max_memory / (1024 * 1024) * 1000)} kB")

                final_grade = total_grade * (100 / total_test_cases)
                st.write(f"### Total : {round(final_grade)}/{100}")
                
                add_row(st.session_state['username'], selected_problem, f"{round(final_grade)}/{100}", f"{round(mxrt * 1000)} ms", f"{round(mxmem / (1024 * 1024) * 1000)} kB")

                # Clean up
                if os.path.exists(source_path):
                    os.remove(source_path)
                if os.path.exists(executable_path):
                    os.remove(executable_path)
        elif code:
            source_path = "submitted_code.cpp"
            executable_path = "./submitted_code"

            with open(source_path, "w") as f:
                f.write(code)

            compile_returncode, compile_stdout, compile_stderr = compile_cpp(source_path, executable_path)

            if compile_returncode != 0:
                st.error(f"Compilation failed:\n{compile_stderr}")
            else:
                total_grade = 0
                total_test_cases = problems[selected_problem]["test_cases"]
                mxrt = 0
                mxmem = 0

                for idx in range(1, total_test_cases + 1):
                    input_url = f"https://raw.githubusercontent.com/Nagornph/Grader_St/main/Problems/{selected_problem}/{idx}.in"
                    input_file = f"./Problems/{selected_problem}/{idx}.in"
                    # download_file(input_url, input_file)

                    expected_output_url = f"https://raw.githubusercontent.com/NagornPh/Grader_St/main/Problems/{selected_problem}/{idx}.out"
                    expected_output_file = f"Problems/{selected_problem}/{idx}.out"
                    # download_file(expected_output_url, expected_output_file)

                    output, errors, runtime, max_memory, returncode = run_executable(executable_path, input_file, problems[selected_problem]["rt"], problems[selected_problem]["mem"])
                    mxrt = max(mxrt, runtime)
                    mxmem = max(mxmem, max_memory)
                    opc, tle, mle = grade(output, expected_output_file, runtime, max_memory, problems[selected_problem]["rt"], problems[selected_problem]["mem"])
                    total_grade += (opc and tle and mle)
                    cw = "Correct Answer" if opc == 1 else "Wrong Answer"
                    cw = "Time Limit Exceed" if tle == 0 else cw
                    cw = "Memory Limit Exceed" if mle == 0 else cw
                    st.write(f" Test Case {idx}\t: {cw} - {round(runtime * 1000)} ms - {round(max_memory / (1024 * 1024) * 1000)} kB")

                final_grade = total_grade * (100 / total_test_cases)
                st.write(f"### Total : {round(final_grade)}/{100}")
                
                add_row(st.session_state['username'], selected_problem, f"{round(final_grade)}/{100}", f"{round(mxrt * 1000)} ms", f"{round(mxmem / (1024 * 1024) * 1000)} kB")

                # Clean up
                if os.path.exists(source_path):
                    os.remove(source_path)
                if os.path.exists(executable_path):
                    os.remove(executable_path)
        else:
            st.error("No code submitted")

# Close the database connection when done
conn.close()
