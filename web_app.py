import os
import threading
import time
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, send_from_directory, flash, jsonify

from crypto_engine import encrypt_file, decrypt_file
from key_manager import KeyRotationManager
from email_alerts import load_email_profiles, send_key_email_with_override
import json

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
ENCRYPTED_DIR = BASE_DIR / "encrypted"
DECRYPTED_DIR = BASE_DIR / "decrypted"
CONFIG_PATH = BASE_DIR / "config.json"

for d in (UPLOAD_DIR, ENCRYPTED_DIR, DECRYPTED_DIR):
    d.mkdir(exist_ok=True)


def load_rotation_interval(default: int = 30) -> int:
    if not CONFIG_PATH.exists():
        return default
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return int(data.get("key_rotation", {}).get("interval_seconds", default))
    except Exception:
        return default


app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-key")  # for flash messages / demo

email_profiles = load_email_profiles()
rotation_interval = load_rotation_interval(default=30)

# Load default email settings from config.json
current_sender_email = None
current_sender_password = None
current_recipient_email = None

if email_profiles:
    profile = email_profiles[0]
    current_sender_email = profile.sender_email
    current_sender_password = profile.sender_password
    if profile.recipients:
        current_recipient_email = profile.recipients[0]

key_manager = KeyRotationManager(
    interval_seconds=rotation_interval,
)


def on_new_password(password: str) -> None:
    # Email the new key only to the currently configured email settings.
    global current_sender_email, current_sender_password, current_recipient_email
    if not (email_profiles and current_sender_email and current_sender_password and current_recipient_email):
        return

    # Use the first email profile as SMTP template (server/port/TLS), but override sender + recipients
    template = email_profiles[0]
    send_key_email_with_override(
        template=template,
        sender_email=current_sender_email,
        sender_password=current_sender_password,
        recipients=[current_recipient_email],
        password=password,
    )


def on_tick(password: str, seconds_left: int) -> None:
    # Web UI will read current values from the manager when rendering templates.
    # Nothing needed here.
    pass


key_manager.on_new_password = on_new_password
key_manager.on_tick = on_tick
key_manager.start()


def _rotation_loop():
    print("Key rotation service started")

    while True:
        try:
            key_manager.tick()
        except Exception as e:
            print("[Rotation Error]", e)

        time.sleep(1)


_rotation_thread = None
_rotation_lock = threading.Lock()

def ensure_rotation_running():
    global _rotation_thread
    if _rotation_thread is None or not _rotation_thread.is_alive():
        with _rotation_lock:
            if _rotation_thread is None or not _rotation_thread.is_alive():
                print("Starting key rotation thread...")
                _rotation_thread = threading.Thread(target=_rotation_loop, daemon=True)
                _rotation_thread.start()


@app.before_request
def start_rotation():
    ensure_rotation_running()

@app.route("/")
def index():
    seconds_left = key_manager.seconds_until_rotation
    return render_template(
        "index.html",
        seconds_left=seconds_left,
        current_recipient=current_recipient_email,
        current_sender=current_sender_email,
    )


@app.route("/set_email_settings", methods=["POST"])
def set_email_settings():
    global current_sender_email, current_sender_password, current_recipient_email
    sender = request.form.get("sender_email", "").strip()
    app_password = request.form.get("sender_password", "").strip()
    receiver = request.form.get("recipient_email", "").strip()

    if not sender or not app_password or not receiver:
        flash("Sender email, app password, and receiver email are all required.", "error")
    else:
        current_sender_email = sender
        current_sender_password = app_password
        current_recipient_email = receiver
        flash(f"Email settings updated. Keys will be sent from {sender} to {receiver}.", "success")

    return redirect(url_for("index"))


@app.route("/api/status")
def api_status():
    """Return current key rotation status as JSON for the front-end."""
    return jsonify(
        currentPassword=key_manager.current_password,
        secondsLeft=key_manager.seconds_until_rotation,
    )


@app.route("/encrypt", methods=["POST"])
def encrypt_route():
    if "file" not in request.files:
        flash("No file part in the request.", "error")
        return redirect(url_for("index"))

    file = request.files["file"]
    if file.filename == "":
        flash("No file selected.", "error")
        return redirect(url_for("index"))

    filename = os.path.basename(file.filename)
    upload_path = UPLOAD_DIR / filename
    file.save(upload_path)

    if not key_manager.current_password:
        flash("Encryption password not ready yet. Please try again in a moment.", "error")
        return redirect(url_for("index"))

    enc_filename = filename + ".enc"
    enc_path = ENCRYPTED_DIR / enc_filename

    try:
        encrypt_file(str(upload_path), str(enc_path), key_manager.current_password)
    except Exception as e:
        flash(f"Encryption failed: {e}", "error")
        return redirect(url_for("index"))

    flash(f"File encrypted successfully as {enc_filename}.", "success")
    return redirect(url_for("download_encrypted", filename=enc_filename))


@app.route("/encrypted/<path:filename>")
def download_encrypted(filename):
    return send_from_directory(ENCRYPTED_DIR, filename, as_attachment=True)


@app.route("/decrypt", methods=["POST"])
def decrypt_route():
    password = request.form.get("password", "").strip()
    if not password:
        flash("Decryption password is required.", "error")
        return redirect(url_for("index"))

    if "enc_file" not in request.files:
        flash("No encrypted file part in the request.", "error")
        return redirect(url_for("index"))

    file = request.files["enc_file"]
    if file.filename == "":
        flash("No encrypted file selected.", "error")
        return redirect(url_for("index"))

    filename = os.path.basename(file.filename)
    upload_path = UPLOAD_DIR / filename
    file.save(upload_path)

    # Build decrypted output filename: keep original extension and append _decrypted before it.
    if filename.endswith(".enc"):
        base = filename[:-4]  # drop .enc -> original name with extension
        name_root, ext = os.path.splitext(base)
        dec_filename = f"{name_root}_decrypted{ext or ''}"
    else:
        name_root, ext = os.path.splitext(filename)
        dec_filename = f"{name_root}_decrypted{ext or ''}"

    dec_path = DECRYPTED_DIR / dec_filename

    try:
        decrypt_file(str(upload_path), str(dec_path), password)
    except Exception as e:
        # Log detailed error to console for debugging (e.g., InvalidTag on wrong password)
        print("[Decrypt] Error while decrypting file:", repr(e))
        flash(
            "Decryption failed: wrong password or this file was encrypted with a different key "
            "(older rotation). Use the key that was active at the time of encryption.",
            "error",
        )
        return redirect(url_for("index"))

    flash(f"File decrypted successfully as {dec_filename}.", "success")
    return send_from_directory(DECRYPTED_DIR, dec_filename, as_attachment=True)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    # Debug mode is fine for development / academic project.
    app.run(host="0.0.0.0", port=port)












