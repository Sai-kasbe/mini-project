import streamlit as st
import pandas as pd
import sqlite3
import hashlib
import os
from datetime import datetime

# Configuration
st.set_page_config(page_title="KGRCET ONLINE ELECTION SYSTEM", layout="wide")

# Style for the app
st.markdown("""
    <style>
    body {
        background-color: #0D1B2A;
        color: white;
    }
    .stButton>button {
        background-color: #1B263B;
        color: white;
        border-radius: 10px;
        padding: 0.5rem 1.5rem;
        margin-top: 10px;
    }
    h1, h2, h3, h4 {
        color: #E0E1DD;
    }
    </style>
""", unsafe_allow_html=True)

# Utility functions
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def get_connection():
    conn = sqlite3.connect("voting.db", check_same_thread=False)
    return conn, conn.cursor()

def authenticate_user(roll_no, password):
    conn, cursor = get_connection()
    cursor.execute("SELECT * FROM users WHERE roll_no=? AND password=?", (roll_no, hash_password(password)))
    row = cursor.fetchone()
    if row:
        return {
            "roll_no": row[0],
            "name": row[1],
            "email": row[3],
            "phone": row[4],
            "image": row[5],
            "has_voted": row[6]
        }
    return None

def add_user(roll_no, name, password, email, phone, image_path):
    conn, cursor = get_connection()
    try:
        cursor.execute("INSERT INTO users (roll_no, name, password, email, phone, image) VALUES (?, ?, ?, ?, ?, ?)",
                       (roll_no, name, hash_password(password), email, phone, image_path))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def record_vote_hash(roll_no, candidate):
    vote_string = roll_no + candidate + datetime.now().isoformat()
    vote_hash = hashlib.sha256(vote_string.encode()).hexdigest()
    conn, cursor = get_connection()
    cursor.execute("INSERT INTO blockchain (roll_no, candidate, vote_hash, timestamp) VALUES (?, ?, ?, ?)",
                   (roll_no, candidate, vote_hash, datetime.now().isoformat()))
    conn.commit()

# Admin credentials
ADMIN_ID = "22QM1A6721"
ADMIN_PASS = hash_password("Sai7@99499")

# User login
def user_login():
    st.subheader("👨‍🎓 User Login")
    roll_no = st.text_input("Roll Number")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if not roll_no or not password:
            st.warning("Please enter both Roll Number and Password.")
            return

        # Authenticate the user from database
        user = authenticate_user(roll_no, password)
        if user:
            st.success(f"Welcome, {user['name']}!")
            st.session_state.user_logged_in = True
            st.session_state.user_data = user
            st.rerun()  # Refresh the app state to load the dashboard
        else:
            st.error("Invalid credentials. Please check your Roll Number or Password.")

# User dashboard
def user_dashboard():
    user = st.session_state.user_data
    st.header("🗳️ Vote Dashboard")
    if user['has_voted']:
        st.success("Status: ✅ VOTED")
    else:
        st.warning("Status: ❌ NOT VOTED")

    conn, cursor = get_connection()
    candidates = pd.read_sql("SELECT * FROM candidates", conn)
    selected = st.radio("Choose your candidate:", candidates['name'])
    
    if st.button("Cast Vote"):
        cursor.execute("UPDATE candidates SET votes = votes + 1 WHERE name=?", (selected,))
        cursor.execute("UPDATE users SET has_voted=1 WHERE roll_no=?", (user['roll_no'],))
        conn.commit()
        record_vote_hash(user['roll_no'], selected)
        st.success("Vote Cast Successfully!")
        st.session_state.user_data['has_voted'] = 1

# Admin login
def admin_login():
    st.subheader("🔐 Admin Login")
    username = st.text_input("Admin ID")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username == ADMIN_ID and hash_password(password) == ADMIN_PASS:
            st.session_state.page = "admin_dashboard"
        else:
            st.error("Invalid admin credentials!")

# Admin dashboard
def admin_dashboard():
    st.header("📊 Admin Dashboard")
    tab1, tab2, tab3 = st.tabs(["➕ Add Candidate", "🧑‍💼 Registered Users", "📢 Result Settings"])

    with tab1:
        st.subheader("Add New Candidate (Role)")
        name = st.text_input("Candidate Name")
        role = st.selectbox("Role", ["President", "Vice-President", "Secretary", "Treasurer"])
        roll_no = st.text_input("roll_no")
        image_file = st.file_uploader("Upload Image", type=["jpg", "png", "jpeg"])

        if st.button("Add Candidate"):
            if not all([name, role, roll_no, image_file]):
                st.error("Please fill in all fields and upload an image.")
            else:
                try:
                    os.makedirs("images", exist_ok=True)
                    image_path = os.path.join("images", image_file.name)
                    with open(image_path, "wb") as f:
                        f.write(image_file.getbuffer())

                    conn, cursor = get_connection()
                    cursor.execute("INSERT INTO candidates (name, roll_no, role, image, votes) VALUES (?, ?, ?, ?, 0)",
                                   (name, party, role, image_path))
                    conn.commit()
                    st.success("Candidate Added Successfully!")
                except Exception as e:
                    st.error(f"Error: {e}")
                finally:
                    conn.close()

    with tab2:
        st.subheader("All Registered Users")
        conn, cursor = get_connection()
        try:
            df = pd.read_sql("SELECT roll_no, name, email, phone, has_voted FROM users", conn)
            st.dataframe(df)
        except Exception as e:
            st.error(f"Failed to load users: {e}")
        finally:
            conn.close()

    with tab3:
        st.subheader("Result Scheduling")
        new_date = st.date_input("Result Date")
        if st.button("Schedule Result"):
            conn, cursor = get_connection()
            cursor.execute("INSERT OR REPLACE INTO result_schedule (id, result_date, is_announced) VALUES (1, ?, 0)", (str(new_date),))
            conn.commit()
            st.success("Result Scheduled!")
        if st.button("Announce Now"):
            conn, cursor = get_connection()
            cursor.execute("UPDATE result_schedule SET is_announced=1 WHERE id=1")
            conn.commit()
            st.success("Result Announced!")

# Main app logic
def main():
    st.title("🏫 KGRCET ONLINE ELECTION SYSTEM")

    if "page" not in st.session_state:
        st.session_state.page = "home"

    if st.session_state.page == "user_dashboard":
        user_dashboard()
        if st.button("Logout"):
            st.session_state.page = "home"
            st.session_state.user_data = None
            st.success("Logged out!")

    elif st.session_state.page == "admin_dashboard":
        admin_dashboard()
        if st.button("Logout"):
            st.session_state.page = "home"
            st.success("Admin logged out!")

    else:
        page = st.sidebar.selectbox("Choose Page", ["Home", "User Login", "Admin Login", "Register", "Forgot Password"])
        if page == "User Login":
            user_login()
        elif page == "Admin Login":
            admin_login()

if __name__ == "__main__":
    main()
