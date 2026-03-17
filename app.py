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


def normalize_user_id(user_id: str) -> str:
    return user_id.strip().upper()


def encode_password(pw: str) -> str:
    return "".join(format(ord(ch), "02x") for ch in pw)


def hash_password(encoded_pw: str) -> str:
    return hashlib.sha256(encoded_pw.encode()).hexdigest()


def parse_password_emojis(password: str):
    """
    Greedy matching against known EMOJIS.
    Returns:
        matched: list of matched emojis
        remainder: non-emoji text left over
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
    prefix = normalize_user_id(user_id)[:1]
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
# STATE
# =========================================================
DEFAULTS = {
    "mode": "Create Password",
    "pending_mode_switch": "",

    "creation_start_time": None,
    "login_start_time": None,

    "create_password": "",
    "login_password": "",

    "create_widget_version": 0,
    "login_widget_version": 0,

    "last_create_pw_type": "",
    "last_login_pw_type": "",

    "create_pending_clear": False,
    "login_pending_clear": False,

    "create_notice": "",
    "login_notice": "",

    "login_attempt_count": 0,
}

for k, v in DEFAULTS.items():
    if k not in st.session_state:
        st.session_state[k] = v

# =========================================================
# APPEND EMOJI HELPERS
# =========================================================
def append_create_emoji(emoji: str):
    current_key = f"create_text_v{st.session_state.create_widget_version}"
    current_text = st.session_state.get(current_key, st.session_state.create_password)
    st.session_state.create_password = current_text + emoji
    st.session_state.create_widget_version += 1


def append_login_emoji(emoji: str):
    current_key = f"login_text_v{st.session_state.login_widget_version}"
    current_text = st.session_state.get(current_key, st.session_state.login_password)
    st.session_state.login_password = current_text + emoji
    st.session_state.login_widget_version += 1

# =========================================================
# PAGE
# =========================================================
st.title("Emoji + Text Password Study Prototype")

st.write(
    "Please enter your assigned Participant ID. "
    "Your category will be detected automatically from the ID prefix (A, B, or C)."
)

participant_id_for_category = st.text_input("Participant ID", key="participant_id_category")
participant_id_for_category = normalize_user_id(participant_id_for_category)

cat_code = get_category_from_user_id(participant_id_for_category)

if cat_code is None:
    st.warning("Please enter a valid Participant ID starting with A, B, or C (e.g. A10, B11, C12).")
    st.stop()

category_info = CATEGORY_MAP[cat_code]
allowed_pw_types = category_info["types"]

st.info(f"You are in Category {cat_code}: {category_info['label']}")

# mode switch BEFORE widget render
if st.session_state.pending_mode_switch:
    st.session_state.mode = st.session_state.pending_mode_switch
    st.session_state.pending_mode_switch = ""

mode = st.radio("Select Mode", ["Create Password", "Login Test"], key="mode")

if cat_code == "A":
    st.write("In this condition, you will create Text and Emoji passwords.")
elif cat_code == "B":
    st.write("In this condition, you will create Text and Hybrid passwords.")
else:
    st.write("In this condition, you will create Text, Emoji, and Hybrid passwords.")

# =========================================================
# CREATE MODE
# =========================================================
if mode == "Create Password":
    st.subheader("Step 1 — Create Password")

    user_id = st.text_input(
        "Participant ID (confirm)",
        value=participant_id_for_category,
        key="create_user_id"
    )
    user_id = normalize_user_id(user_id)

    detected_cat = get_category_from_user_id(user_id)

    if detected_cat != cat_code:
        st.error("The Participant ID does not match the detected category.")
        st.stop()

    pw_type = st.selectbox("Password Type", allowed_pw_types, key="pw_type_create")

    # Type switch
    if pw_type != st.session_state.last_create_pw_type:
        st.session_state.create_password = ""
        st.session_state.create_widget_version += 1
        st.session_state.last_create_pw_type = pw_type
        st.session_state.creation_start_time = None

    # Timer
    if st.session_state.creation_start_time is None:
        st.session_state.creation_start_time = time.time()

    # Pending clear
    if st.session_state.create_pending_clear:
        st.session_state.create_password = ""
        st.session_state.create_widget_version += 1
        st.session_state.create_pending_clear = False

    if st.session_state.create_notice:
        st.success(st.session_state.create_notice)
        st.session_state.create_notice = ""

    if pw_type in ["Emoji", "Hybrid"]:
        st.write("Click emojis to add to your password:")
        cols = st.columns(8)
        for i, emoji in enumerate(EMOJIS):
            with cols[i % 8]:
                if st.button(emoji, key=f"create_emoji_{i}_{pw_type}"):
                    append_create_emoji(emoji)
                    st.rerun()

    if pw_type == "Emoji":
        st.text_input(
            "Password (Emoji only — typing disabled)",
            value=st.session_state.create_password,
            key=f"create_display_v{st.session_state.create_widget_version}",
            type="password",
            disabled=True,
        )
        password = st.session_state.create_password
    else:
        typed = st.text_input(
            "Password (Type text or click emojis)",
            value=st.session_state.create_password,
            key=f"create_text_v{st.session_state.create_widget_version}",
            type="password",
        )
        password = typed
        st.session_state.create_password = typed

    c1, c2 = st.columns(2)

    with c1:
        if st.button("Clear Password", key="clear_create"):
            st.session_state.create_pending_clear = True
            st.rerun()

    with c2:
        if st.button("Save Password", key="save_create"):
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
                        existing_user_id = normalize_user_id(str(r.get("user_id", "")))
                        if (
                            existing_user_id == str(user_id)
                            and r.get("type", "") == pw_type
                            and r.get("event", "") == "created"
                        ):
                            duplicate = True
                            break

                    if duplicate:
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

                        # auto switch to login, safely
                        st.session_state.creation_start_time = None
                        st.session_state.create_pending_clear = True
                        st.session_state.pending_mode_switch = "Login Test"
                        st.session_state.login_notice = (
                            f"Password saved for {pw_type}. "
                            f"Please now complete the Login Test using the same Participant ID and password type."
                        )
                        st.rerun()

# =========================================================
# LOGIN MODE
# =========================================================
if mode == "Login Test":
    st.subheader("Step 2 — Login")

    user_id = st.text_input(
        "Participant ID (confirm)",
        value=participant_id_for_category,
        key="login_user_id"
    )
    user_id = normalize_user_id(user_id)

    detected_cat = get_category_from_user_id(user_id)

    if detected_cat != cat_code:
        st.error("The Participant ID does not match the detected category.")
        st.stop()

    pw_type = st.selectbox("Password Type", allowed_pw_types, key="pw_type_login")
    session_type = st.selectbox("Session Type", ["Immediate", "Delayed"], key="session_type_login")

    # Type switch
    if pw_type != st.session_state.last_login_pw_type:
        st.session_state.login_password = ""
        st.session_state.login_widget_version += 1
        st.session_state.last_login_pw_type = pw_type
        st.session_state.login_start_time = None
        st.session_state.login_attempt_count = 0

    # Timer
    if st.session_state.login_start_time is None:
        st.session_state.login_start_time = time.time()

    # Pending clear
    if st.session_state.login_pending_clear:
        st.session_state.login_password = ""
        st.session_state.login_widget_version += 1
        st.session_state.login_pending_clear = False

    if st.session_state.login_notice:
        st.success(st.session_state.login_notice)
        st.session_state.login_notice = ""

    if pw_type in ["Emoji", "Hybrid"]:
        st.write("Click emojis to add to your password:")
        cols = st.columns(8)
        for i, emoji in enumerate(EMOJIS):
            with cols[i % 8]:
                if st.button(emoji, key=f"login_emoji_{i}_{pw_type}"):
                    append_login_emoji(emoji)
                    st.rerun()

    if pw_type == "Emoji":
        st.text_input(
            "Password (Emoji only — typing disabled)",
            value=st.session_state.login_password,
            key=f"login_display_v{st.session_state.login_widget_version}",
            type="password",
            disabled=True,
        )
        password = st.session_state.login_password
    else:
        typed = st.text_input(
            "Password (Type text or click emojis)",
            value=st.session_state.login_password,
            key=f"login_text_v{st.session_state.login_widget_version}",
            type="password",
        )
        password = typed
        st.session_state.login_password = typed

    c1, c2 = st.columns(2)

    with c1:
        if st.button("Clear Password", key="clear_login"):
            st.session_state.login_pending_clear = True
            st.rerun()

    with c2:
        if st.button("Login", key="do_login"):
            if not user_id or password == "":
                st.warning("Please fill all fields.")
                st.stop()

            valid, message = validate_password_by_type(password, pw_type)
            if not valid:
                st.error(message)
                st.stop()

            record = get_created_record(user_id, pw_type)
            if record is None:
                st.error("No created password found for this Participant ID and Password Type.")
                st.stop()

            encoded = encode_password(password)
            hashed = hash_password(encoded)
            login_time = round(time.time() - st.session_state.login_start_time, 3)

            st.session_state.login_attempt_count += 1
            success = hashed == record["hash"]

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
                st.session_state.login_start_time = None
                st.session_state.login_attempt_count = 0
                st.session_state.login_pending_clear = True
                st.session_state.login_notice = "Login Successful. You may now continue to the questionnaire."
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
        if st.button("Prepare Download"):
            records = get_all_records_safe()
            logs = pd.DataFrame(records)
            if not logs.empty:
                csv = logs.to_csv(index=False).encode("utf-8")
                st.download_button("Click to Download logs.csv", csv, "logs.csv", "text/csv")
    elif researcher_code:
        st.error("Invalid access code.")
