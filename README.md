## Secure File Sharing and Steganography Platform

A Python/Flask web application for **securely sharing files and text messages** by encrypting them and hiding them inside images using **steganography**.

---

## Features

- **User accounts**
  - Signup, login, logout, and session management
  - User data stored in SQLite

- **Secure file sharing**
  - Upload files and share them with selected users
  - Symmetric encryption using **Blowfish** and **ChaCha20**
  - Per-recipient keys stored in the database

- **Image steganography (files in images)**
  - Hide an uploaded file inside a cover image using **LSB (least significant bit)** manipulation
  - Generate a stego-image that visually looks like the original cover image
  - Decode and recover the hidden data for authorized users

- **Text steganography (messages in images)**
  - Hide arbitrary text messages inside images via LSB-based encoding
  - Support for extracting and displaying the hidden text

- **Access control and approvals**
  - Users can request access to shared content
  - Owners receive notifications and can approve/deny
  - Only approved users can decrypt and view hidden content

---

## Tech Stack

- **Backend**: Python, Flask
- **Database**: SQLite (`store.db`)
- **Crypto**:
  - `blowfish` for block cipher file encryption
  - `cryptography` (ChaCha20) for additional file encryption
- **Image processing / steganography**:
  - OpenCV (`cv2`)
  - Pillow (`PIL`)
  - NumPy
- **Frontend**:
  - HTML templates (Jinja2)
  - CSS/JS (static assets in `static/`)

---

## Project Structure (simplified)

- `main.py` – Flask app entry point, routes, encryption and steganography logic
- `image.py` – image-related helper logic (if used)
- `textstenography.py` – text steganography helpers (encode/decode text in images)
- `templates/` – HTML templates (login, signup, dashboard, upload, view shared items, etc.)
- `static/`
  - `css/` – stylesheets
  - `js/` – client-side scripts
- `upload/` – uploaded and intermediate files (cover and secret images, text images, etc.)
- `static/col/` – images containing hidden data (stego-images)
- `static/decrypt/` – decrypted output files/images
- `store.db` – SQLite database

---

## Database Setup

The application uses a SQLite database file `store.db` with tables such as:

- `data` – users (user id, name, email, password)
- `sharing` – shared file metadata
- `sharingtable` – per-user file sharing entries and keys
- `requesttable` – access requests and statuses
- `textstenography` – text steganography entries

In many setups this DB is created and evolved via `sqlite3` and the commented `CREATE TABLE` statements in `main.py` and related files. For a fresh environment:

1. Ensure `store.db` exists in the project root.
2. Use `sqlite3 store.db` (or a GUI) to create the tables according to the schema used in `main.py` (or reuse an existing `store.db` from a working environment).

---

## Running the Application

From the project root (with the virtual environment active):

```bash
python main.py
```

By default, Flask will start in debug mode on:

```text
http://127.0.0.1:5000/
```

Open this URL in your browser.

---

## Basic Usage

1. **Register and login**
   - Go to the homepage and create a new account.
   - Log in with your credentials.

2. **Hide and share a file in an image**
   - Navigate to the file/image steganography page.
   - Upload a **cover image** and a **file** to hide.
   - Choose which users to share with.
   - The app creates a stego-image and records sharing metadata.

3. **Request access & approvals**
   - Recipients can view shared items and request access.
   - Owners see notifications and can approve requests.
   - Approved users receive the necessary key to decrypt.

4. **Decrypt and view**
   - Once approved, the recipient can decrypt the file.
   - Hidden content is recovered into `static/decrypt/` and shown in the UI.

5. **Text steganography**
   - Navigate to the text steganography page.
   - Upload a cover image and enter the message text.
   - The app encodes the text inside the image and allows later decoding/display.

---

## Security Notes

- This project is primarily a **demonstration / educational** implementation of encryption and steganography.
- Keys are generated and stored in SQLite; hard-coded secrets (e.g., Flask `secret_key`) and debug mode are **not production-safe**.
- For real-world deployments, you should:
  - Use strong, environment-based secrets and configuration.
  - Enforce HTTPS, strong authentication, and better key management.
  - Audit and harden the crypto and steganography code paths.

---