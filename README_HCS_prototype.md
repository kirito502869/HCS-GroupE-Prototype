# HCS Group Project Prototype

## Instructions for Running the Streamlit Application

This project contains a browser-based Streamlit prototype developed for the Human-Centred Security group project on emoji-based passwords.

## 1. Requirements

Before running the prototype, make sure the following are installed:

- Python 3.10 or above
- pip
- Internet access (required for Google Sheets logging)

The required Python packages are listed in `requirements.txt`.

## 2. Installation

Open a terminal in the project folder and install the dependencies:

```bash
pip install -r requirements.txt
```

## 3. Google Sheets Setup

This prototype stores behavioural logs in Google Sheets. To run the application successfully, a valid Google service account configuration must be provided in Streamlit secrets.

Create a `.streamlit/secrets.toml` file and include:

```toml
[gcp_service_account]
type = "service_account"
project_id = "YOUR_PROJECT_ID"
private_key_id = "YOUR_PRIVATE_KEY_ID"
private_key = "YOUR_PRIVATE_KEY"
client_email = "YOUR_CLIENT_EMAIL"
client_id = "YOUR_CLIENT_ID"
auth_uri = "https://accounts.google.com/o/oauth2/auth"
token_uri = "https://oauth2.googleapis.com/token"
auth_provider_x509_cert_url = "https://www.googleapis.com/oauth2/v1/certs"
client_x509_cert_url = "YOUR_CLIENT_CERT_URL"
```

The application expects a Google Sheet named:

```text
streamlit_logs
```

The service account must have permission to access and edit this sheet.

## 4. Running the Prototype

Start the Streamlit app with:

```bash
streamlit run app.py
```

The application will then open in a browser window.

## 5. Prototype Overview

The prototype supports three password types:

- **Text-only**
- **Emoji-only**
- **Hybrid (Text + Emoji)**

Participant category is determined automatically from the first letter of the Participant ID:

- **A** → Text + Emoji
- **B** → Text + Hybrid
- **C** → Text + Emoji + Hybrid

Example Participant IDs:

- `A10`
- `B11`
- `C12`

## 6. Study Flow

### Step 1: Password Creation

Participants first enter their Participant ID. The system automatically determines the assigned study condition.

In **Create Password** mode, participants:

1. Select a password type allowed for their condition
2. Create a password
3. Save the password

For Emoji and Hybrid conditions, the interface provides an emoji picker so that emoji entry does not depend on operating-system-specific keyboards.

### Step 2: Login Test

After all required password types have been created, participants move to **Login Test** mode.

In this stage, participants:

1. Select the password type
2. Select the session type (`Immediate` or `Delayed`)
3. Enter the created password
4. Attempt login

Successful and failed login attempts are logged automatically.

## 7. Security and Logging

### Password handling

Passwords are **not stored in plain text**.

Before storage:

1. The password is converted into hexadecimal character codes
2. The encoded string is hashed using **SHA-256**

Only the resulting hash is stored in the log.

### Logged data

The prototype records the following fields in Google Sheets:

- `timestamp`
- `user_id`
- `type`
- `category`
- `session_type`
- `event`
- `reason`
- `password_length`
- `emoji_count`
- `creation_time`
- `hash`
- `success`
- `login_time`
- `attempt_length`
- `attempt_number`

## 8. Researcher Controls

The prototype includes a protected **Researcher Controls** section.

To access it, enter the researcher access code:

```text
test2026
```

This allows the researcher to download the behavioural log file as `logs.csv`.

## 9. Notes

- Password input is masked during both creation and login.
- Emoji-only passwords must contain only emojis from the provided emoji set.
- Hybrid passwords must contain both text and emojis.
- Text-only passwords must not contain emojis.
- If the Google Sheets credentials are missing or invalid, logging will not function correctly.

## 10. Project Purpose

This prototype was developed to evaluate whether emoji-based passwords can support a better balance between usability and perceived security in a browser-based authentication setting.

It was used to compare:

- ease of creation
- login performance
- creation success
- login success
- password composition
- user perceptions of memorability, security, and real-life preference
