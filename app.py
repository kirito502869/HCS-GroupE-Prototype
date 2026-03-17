import hashlib
import time
from datetime import datetime

import gspread
import pandas as pd
import streamlit as st
from google.oauth2.service_account import Credentials

# =========================================================
# CONFIG
# =========================================================
RESEARCHER_ACCESS_CODE = "test2026"
SHEET_NAME = "streamlit_logs"

EMOJIS = ["😀", "😂", "🔥", "😊", "😎", "👍", "🎉", "😢", "🚀", "🥶", "🤖", "👀", "💀", "🌙", "⭐", "🍕"]

CATEGORY_MAP = {
    "A": {"label": "A - Text + Emoji", "types": ["Text", "Emoji"]},
    "B": {"label": "B - Text + Hybrid", "types": ["Text", "Hybrid"]},
    "C": {"label": "C - Text + Emoji + Hybrid", "types": ["Text", "Emoji", "Hybrid"]},
}

REQUIRED_HEADERS = [
    "timestamp",
    "user_id",
    "type",
    "category",
    "session_type",
    "event",
    "reason",
    "password_length",
    "emoji_count",
    "creation_time",
    "hash",
    "success",
    "login_time",
    "attempt_length",
    "attempt_number",
]

# =========================================================
# GOOGLE SHEETS
# =========================================================
@st.cache_resource
def get_sheet():
    scope = [
        "https://www.googleapis.com/auth/spreadsheets",
        "https://www.googleapis.com/auth/drive",
    ]
    creds = Credentials.from_service_account_info(
        st.secrets["gcp_service_account"],
        scopes=scope,
    )
    client = gspread.authorize(creds)
    return client.open(SHEET_NAME).sheet1


sheet = get_sheet()


def ensure_headers():
    headers = sheet.row_values(1)
    if not headers:
        sheet.append_row(REQUIRED_HEADERS)


ensure_headers()

# =========================================================
# HELPERS
# =========================================================
def now_iso():
    return datetime.now().isoformat()


def encode_password(pw: str) -> str:
    return "".join(format(ord(ch), "02x") for ch in pw)


def hash_password(encoded_pw: str) -> str:
    return hashlib.sha256(encoded_pw.encode()).hexdigest()


def parse_password_emojis(password: str):
    """
    Greedy matching against known EMOJIS.
    Returns:
        matched_emojis: list[str]
        remainder: str  # everything not matched as one of the known emojis
    """
    emoji_list = sorted(EMOJIS, key=len, reverse=True)
    matched = []
    remainder = []

    i = 0
    while i < len(password):
        found = False
        for e in emoji_list:
            if password.startswith(e, i):
                matched.append(e)
                i += len(e)
                found = True
                break
        if not found:
            remainder.append(password[i])
            i += 1

    return matched, "".join(remainder)


def count_known_emojis(password: str) -> int:
    matched, _ = parse_password_emojis(password)
    return len(matched)


def is_emoji_only_password(password: str) -> bool:
    matched, remainder = parse_password_emojis(password)
    return len(matched) > 0 and remainder == ""


def has_any_known_emoji(password: str) -> bool:
    matched, _ = parse_password_emojis(password)
    return len(matched) > 0


def has_any_text(password: str) -> bool:
    _, remainder = parse_password_emojis(password)
    return remainder != ""


def validate_password_by_type(password: str, pw_type: str):
    if password == "":
        return False, "Password cannot be empty."

    if pw_type == "Text":
        if has_any_known_emoji(password):
            return False, "Text passwords cannot contain emojis."
        return True, ""

    if pw_type == "Emoji":
        if not is_emoji_only_password(password):
            return False, "Emoji passwords can only contain emojis."
        return True, ""

    if pw_type == "Hybrid":
        if not has_any_known_emoji(password) or not has_any_text(password):
            return False, "Hybrid passwords must contain both text and emojis."
        return True, ""

    return False, "Invalid password type."


def get_category_from_user_id(user_id: str):
    if not user_id:
        return None
    prefix = user_id.strip().upper()[:1]
    return prefix if prefix in CATEGORY_MAP else None


def save_log(data: dict):
    headers = sheet.row_values(1)
    if not headers:
        headers = REQUIRED_HEADERS
        sheet.append_row(headers)

    row = [data.get(col, "") for col in headers]
    sheet.append_row(row)


def get_all_records_safe():
    try:
        return sheet.get_all_records()
    except Exception:
        return []


def get_created_record(user_id: str, pw_type: str):
    records = get_all_records_safe()
    if not records:
        return None

    logs = pd.DataFrame(records)
    if logs.empty:
        return None

    required_cols = {"user_id", "type", "event", "hash"}
    if not required_cols.issubset(set(logs.columns)):
        return None

    filtered = logs[
        (logs["user_id"].astype(str) == str(user_id))
        & (logs["type"] == pw_type)
        & (logs["event"] == "created")
    ]

    if filtered.empty:
        return None

    return filtered.iloc[-1]

# =========================================================
# SESSION STATE DEFAULTS
# =========================================================
DEFAULTS = {
    "creation_start_time": None,
    "login_start_time": None,

    "create_password": "",
    "login_password": "",

    "create_text_widget": "",
    "login_text_widget": "",

    "last_create_pw_type": "",
    "last_login_pw_type": "",

    "create_notice": "",
    "login_notice": "",

    "login_attempt_count": 0,
}

for k, v in DEFAULTS.items():
    if k not in st.session_state:
        st.session_state[k] = v

# =========================================================
# CALLBACKS - CREATE MODE
# =========================================================
def create_sync_from_text():
    st.session_state.create_password = st.session_state.create_text_widget


def create_append_emoji(emoji: str):
    st.session_state.create_password += emoji
    current_type = st.session_state.get("pw_type_create", "")
    if current_type in ["Text", "Hybrid"]:
        st.session_state.create_text_widget = st.session_state.create_password


def create_clear():
    st.session_state.create_password = ""
    st.session_state.create_text_widget = ""


def create_reset_for_type_change():
    st.session_state.create_password = ""
    st.session_state.create_text_widget = ""
    st.session_state.creation_start_time = None

# =========================================================
# CALLBACKS - LOGIN MODE
# =========================================================
def login_sync_from_text():
    st.session_state.login_password = st.session_state.login_text_widget


def login_append_emoji(emoji: str):
    st.session_state.login_password += emoji
    current_type = st.session_state.get("pw_type_login", "")
    if current_type in ["Text", "Hybrid"]:
        st.session_state.login_text_widget = st.session_state.login_password


def login_clear():
    st.session_state.login_password = ""
    st.session_state.login_text_widget = ""


def login_reset_for_type_change():
    st.session_state.login_password = ""
    st.session_state.login_text_widget = ""
    st.session_state.login_start_time = None
    st.session_state.login_attempt_count = 0

# =========================================================
# PAGE UI
# =========================================================
st.title("Emoji + Text Password Study Prototype")

st.write(
    "Please enter your assigned Participant ID. "
    "Your category will be detected automatically from the ID prefix (A, B, or C)."
)

participant_id_for_category = st.text_input("Participant ID", key="participant_id_category")
cat_code = get_category_from_user_id(participant_id_for_category)

if cat_code is None:
    st.warning("Please enter a valid Participant ID starting with A, B, or C (e.g. A10, B11, C12).")
    st.stop()

category_info = CATEGORY_MAP[cat_code]
allowed_pw_types = category_info["types"]

st.info(f"You are in Category {cat_code}: {category_info['label']}")

mode = st.radio("Select Mode", ["Create Password", "Login Test"])

if cat_code == "A":
    st.write("In this condition, you will create Text and Emoji passwords.")
elif cat_code == "B":
    st.write("In this condition, you will create Text and Hybrid passwords.")
else:
    st.write("In this condition, you will create Text, Emoji, and Hybrid passwords.")

# =========================================================
# CREATE PASSWORD MODE
# =========================================================
if mode == "Create Password":
    st.subheader("Step 1 — Create Password")

    user_id = st.text_input("Participant ID (confirm)", value=participant_id_for_category, key="create_user_id")
    detected_cat = get_category_from_user_id(user_id)

    if detected_cat != cat_code:
        st.error("The Participant ID does not match the detected category. Please check your ID.")
        st.stop()

    pw_type = st.selectbox(
        "Password Type",
        allowed_pw_types,
        key="pw_type_create",
        on_change=create_reset_for_type_change,
    )

    if st.session_state.creation_start_time is None:
        st.session_state.creation_start_time = time.time()

    if st.session_state.create_notice:
        st.success(st.session_state.create_notice)
        st.session_state.create_notice = ""

    if pw_type in ["Emoji", "Hybrid"]:
        st.write("Click emojis to add to your password:")
        cols = st.columns(8)
        for i, emoji in enumerate(EMOJIS):
            with cols[i % 8]:
                st.button(
                    emoji,
                    key=f"create_emoji_button_{i}_{pw_type}",
                    on_click=create_append_emoji,
                    args=(emoji,),
                )

    if pw_type == "Emoji":
        st.text_input(
            "Password (Emoji only — typing disabled)",
            value=st.session_state.create_password,
            key="create_emoji_display",
            type="password",
            disabled=True,
        )
    else:
        if st.session_state.create_text_widget != st.session_state.create_password:
            st.session_state.create_text_widget = st.session_state.create_password

        st.text_input(
            "Password (Type text or click emojis)",
            key="create_text_widget",
            type="password",
            on_change=create_sync_from_text,
        )

    col1, col2 = st.columns(2)

    with col1:
        st.button("Clear Password", key="clear_create_password", on_click=create_clear)

    with col2:
        if st.button("Save Password", key="save_create_password"):
            password = st.session_state.create_password

            if not user_id or password == "":
                st.warning("Please fill all fields.")
            else:
                valid, message = validate_password_by_type(password, pw_type)

                if not valid:
                    st.error(message)
                    save_log({
                        "timestamp": now_iso(),
                        "user_id": user_id,
                        "type": pw_type,
                        "category": cat_code,
                        "session_type": "",
                        "event": "creation_failed",
                        "reason": message,
                        "password_length": len(password),
                        "emoji_count": count_known_emojis(password),
                        "creation_time": round(time.time() - st.session_state.creation_start_time, 3),
                        "hash": "",
                        "success": "",
                        "login_time": "",
                        "attempt_length": "",
                        "attempt_number": "",
                    })
                else:
                    records = get_all_records_safe()
                    duplicate = False

                    for r in records:
                        if (
                            str(r.get("user_id", "")) == str(user_id)
                            and r.get("type", "") == pw_type
                            and r.get("event", "") == "created"
                        ):
                            duplicate = True
                            break

                    if duplicate:
                        save_log({
                            "timestamp": now_iso(),
                            "user_id": user_id,
                            "type": pw_type,
                            "category": cat_code,
                            "session_type": "",
                            "event": "creation_failed",
                            "reason": "duplicate_user_id_for_type",
                            "password_length": len(password),
                            "emoji_count": count_known_emojis(password),
                            "creation_time": round(time.time() - st.session_state.creation_start_time, 3),
                            "hash": "",
                            "success": "",
                            "login_time": "",
                            "attempt_length": "",
                            "attempt_number": "",
                        })
                        st.error(f"This Participant ID has already created a {pw_type} password.")
                    else:
                        encoded = encode_password(password)
                        hashed = hash_password(encoded)
                        creation_time = round(time.time() - st.session_state.creation_start_time, 3)

                        save_log({
                            "timestamp": now_iso(),
                            "user_id": user_id,
                            "type": pw_type,
                            "category": cat_code,
                            "session_type": "",
                            "event": "created",
                            "reason": "",
                            "password_length": len(password),
                            "emoji_count": count_known_emojis(password),
                            "creation_time": creation_time,
                            "hash": hashed,
                            "success": "",
                            "login_time": "",
                            "attempt_length": "",
                            "attempt_number": "",
                        })

                        create_clear()
                        st.session_state.creation_start_time = None
                        st.session_state.create_notice = "Password saved. Please proceed to Login Test after a short break."
                        st.rerun()

# =========================================================
# LOGIN TEST MODE
# =========================================================
if mode == "Login Test":
    st.subheader("Step 2 — Login")

    user_id = st.text_input("Participant ID (confirm)", value=participant_id_for_category, key="login_user_id")
    detected_cat = get_category_from_user_id(user_id)

    if detected_cat != cat_code:
        st.error("The Participant ID does not match the detected category. Please check your ID.")
        st.stop()

    pw_type = st.selectbox(
        "Password Type",
        allowed_pw_types,
        key="pw_type_login",
        on_change=login_reset_for_type_change,
    )

    session_type = st.selectbox("Session Type", ["Immediate", "Delayed"], key="session_type_login")

    if st.session_state.login_start_time is None:
        st.session_state.login_start_time = time.time()

    if st.session_state.login_notice:
        st.success(st.session_state.login_notice)
        st.session_state.login_notice = ""

    if pw_type in ["Emoji", "Hybrid"]:
        st.write("Click emojis to add to your password:")
        cols = st.columns(8)
        for i, emoji in enumerate(EMOJIS):
            with cols[i % 8]:
                st.button(
                    emoji,
                    key=f"login_emoji_button_{i}_{pw_type}",
                    on_click=login_append_emoji,
                    args=(emoji,),
                )

    if pw_type == "Emoji":
        st.text_input(
            "Password (Emoji only — typing disabled)",
            value=st.session_state.login_password,
            key="login_emoji_display",
            type="password",
            disabled=True,
        )
    else:
        if st.session_state.login_text_widget != st.session_state.login_password:
            st.session_state.login_text_widget = st.session_state.login_password

        st.text_input(
            "Password (Type text or click emojis)",
            key="login_text_widget",
            type="password",
            on_change=login_sync_from_text,
        )

    col1, col2 = st.columns(2)

    with col1:
        st.button("Clear Password", key="clear_login_password", on_click=login_clear)

    with col2:
        if st.button("Login", key="login_button"):
            password = st.session_state.login_password

            if not user_id or password == "":
                st.warning("Please fill all fields.")
                st.stop()

            valid, message = validate_password_by_type(password, pw_type)
            if not valid:
                st.error(message)
                save_log({
                    "timestamp": now_iso(),
                    "user_id": user_id,
                    "type": pw_type,
                    "category": cat_code,
                    "session_type": session_type,
                    "event": "login_failed_validation",
                    "reason": message,
                    "password_length": "",
                    "emoji_count": "",
                    "creation_time": "",
                    "hash": "",
                    "success": False,
                    "login_time": "",
                    "attempt_length": len(password),
                    "attempt_number": st.session_state.login_attempt_count + 1,
                })
                st.stop()

            record = get_created_record(user_id, pw_type)

            if record is None:
                st.error("No created password found for this Participant ID and Password Type.")
                save_log({
                    "timestamp": now_iso(),
                    "user_id": user_id,
                    "type": pw_type,
                    "category": cat_code,
                    "session_type": session_type,
                    "event": "login_failed_no_record",
                    "reason": "no_created_password_found",
                    "password_length": "",
                    "emoji_count": "",
                    "creation_time": "",
                    "hash": "",
                    "success": False,
                    "login_time": "",
                    "attempt_length": len(password),
                    "attempt_number": st.session_state.login_attempt_count + 1,
                })
                st.stop()

            encoded = encode_password(password)
            hashed = hash_password(encoded)
            login_time = round(time.time() - st.session_state.login_start_time, 3)

            st.session_state.login_attempt_count += 1
            success = (hashed == record["hash"])

            save_log({
                "timestamp": now_iso(),
                "user_id": user_id,
                "type": pw_type,
                "category": cat_code,
                "session_type": session_type,
                "event": "login",
                "reason": "",
                "password_length": "",
                "emoji_count": "",
                "creation_time": "",
                "hash": "",
                "success": success,
                "login_time": login_time,
                "attempt_length": len(password),
                "attempt_number": st.session_state.login_attempt_count,
            })

            if success:
                login_clear()
                st.session_state.login_start_time = None
                st.session_state.login_attempt_count = 0
                st.session_state.login_notice = "Login Successful"
                st.rerun()
            else:
                st.error("Login Failed")

# =========================================================
# RESEARCHER CONTROLS
# =========================================================
st.divider()
with st.expander("Researcher Controls"):
    researcher_code = st.text_input("Enter researcher access code", type="password", key="researcher_access")

    if researcher_code == RESEARCHER_ACCESS_CODE:
        st.success("Researcher access granted.")

        if st.button("Show Summary"):
            records = get_all_records_safe()
            logs = pd.DataFrame(records)

            if logs.empty:
                st.info("No logs found yet.")
            else:
                st.write(f"Total records: {len(logs)}")

                if "event" in logs.columns:
                    st.write("Event counts:")
                    event_counts = logs["event"].value_counts().reset_index()
                    event_counts.columns = ["event", "count"]
                    st.dataframe(event_counts, use_container_width=True)

                if "user_id" in logs.columns:
                    st.write(f"Unique participant IDs: {logs['user_id'].astype(str).nunique()}")

        if st.button("Prepare Download"):
            records = get_all_records_safe()
            logs = pd.DataFrame(records)

            if logs.empty:
                st.warning("No logs found yet.")
            else:
                csv = logs.to_csv(index=False).encode("utf-8")
                st.download_button(
                    label="Click to Download logs.csv",
                    data=csv,
                    file_name="logs.csv",
                    mime="text/csv",
                )

    elif researcher_code:
        st.error("Invalid access code.")
