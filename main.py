import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, scrolledtext
from pathlib import Path
from typing import Optional

from crypto_engine import encrypt_file, decrypt_file
from key_manager import KeyRotationManager
from email_alerts import load_email_profiles, send_key_email_to_all
import json


CONFIG_PATH = Path(__file__).with_name("config.json")


def load_rotation_interval(default: int = 30) -> int:
    if not CONFIG_PATH.exists():
        return default
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return int(data.get("key_rotation", {}).get("interval_seconds", default))
    except Exception:
        return default


class App:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Advanced File Protection System")
        self.root.geometry("700x450")

        self.selected_file: Optional[Path] = None

        # Load config (supporting multiple email profiles)
        self.email_profiles = load_email_profiles()
        interval = load_rotation_interval(default=30)

        # Key rotation manager
        self.key_manager = KeyRotationManager(
            interval_seconds=interval,
            on_new_password=self._on_new_password,
            on_tick=self._on_tick,
        )

        self._build_gui()
        self.key_manager.start()

        # Start periodic tick (1 second)
        self._schedule_tick()

    # GUI setup
    def _build_gui(self) -> None:
        frame_top = tk.Frame(self.root)
        frame_top.pack(fill=tk.X, padx=10, pady=10)

        btn_select = tk.Button(frame_top, text="Select File", command=self.select_file)
        btn_select.pack(side=tk.LEFT)

        self.lbl_selected = tk.Label(frame_top, text="No file selected", anchor="w")
        self.lbl_selected.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)

        frame_mid = tk.Frame(self.root)
        frame_mid.pack(fill=tk.X, padx=10, pady=5)

        self.lbl_password = tk.Label(frame_mid, text="Current Password: (generating...)", anchor="w")
        self.lbl_password.pack(fill=tk.X)

        self.lbl_countdown = tk.Label(frame_mid, text="Next rotation in: -- s", anchor="w")
        self.lbl_countdown.pack(fill=tk.X, pady=(2, 0))

        frame_buttons = tk.Frame(self.root)
        frame_buttons.pack(fill=tk.X, padx=10, pady=10)

        btn_encrypt = tk.Button(frame_buttons, text="Encrypt Selected File", command=self.encrypt_selected)
        btn_encrypt.pack(side=tk.LEFT, padx=5)

        btn_decrypt = tk.Button(frame_buttons, text="Decrypt File", command=self.decrypt_file_dialog)
        btn_decrypt.pack(side=tk.LEFT, padx=5)

        frame_log = tk.Frame(self.root)
        frame_log.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        tk.Label(frame_log, text="Event Log:").pack(anchor="w")

        self.txt_log = scrolledtext.ScrolledText(frame_log, height=12, state="disabled")
        self.txt_log.pack(fill=tk.BOTH, expand=True)

    def log(self, message: str) -> None:
        self.txt_log.configure(state="normal")
        self.txt_log.insert(tk.END, message + "\n")
        self.txt_log.see(tk.END)
        self.txt_log.configure(state="disabled")

    # Key rotation callbacks
    def _on_new_password(self, password: str) -> None:
        # Update label
        self.lbl_password.config(text=f"Current Password: {password}")
        self.log("[KeyRotation] New password generated and displayed.")

        # Send email if profiles are available
        if not self.email_profiles:
            self.log("[Email] Email configuration not found. Skipping email notification.")
        else:
            self.log("[Email] Sending new password to configured recipients via all profiles...")
            send_key_email_to_all(self.email_profiles, password)

    def _on_tick(self, password: str, seconds_left: int) -> None:
        self.lbl_countdown.config(text=f"Next rotation in: {seconds_left} s")

    def _schedule_tick(self) -> None:
        self.key_manager.tick()
        self.root.after(1000, self._schedule_tick)

    # File operations
    def select_file(self) -> None:
        filename = filedialog.askopenfilename(title="Select file to encrypt")
        if filename:
            self.selected_file = Path(filename)
            self.lbl_selected.config(text=str(self.selected_file))
            self.log(f"[File] Selected file: {self.selected_file}")

    def encrypt_selected(self) -> None:
        if self.selected_file is None:
            messagebox.showwarning("No file selected", "Please select a file to encrypt.")
            return

        password = self.key_manager.current_password
        if not password:
            messagebox.showerror("Password not ready", "Encryption password is not ready yet. Please wait a moment.")
            return

        input_path = str(self.selected_file)
        output_path = input_path + ".enc"

        try:
            encrypt_file(input_path, output_path, password)
            self.log(f"[Encrypt] Encrypted '{input_path}' -> '{output_path}' using current password.")
            messagebox.showinfo("Success", f"File encrypted to:\n{output_path}")
        except Exception as e:
            self.log(f"[Error] Encryption failed: {e}")
            messagebox.showerror("Error", f"Encryption failed:\n{e}")

    def decrypt_file_dialog(self) -> None:
        enc_path = filedialog.askopenfilename(title="Select encrypted file", filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")])
        if not enc_path:
            return

        password = simpledialog.askstring(
            "Decryption Password",
            "Enter the password that was active when the file was encrypted (check your email):",
            show="*",
        )
        if password is None:
            return
        password = password.strip()
        if password == "":
            return

        input_path = Path(enc_path)
        # Build decrypted output path: keep original extension and append _decrypted before it.
        if input_path.suffix == ".enc":
            base = input_path.with_suffix("")  # drop .enc -> original filename with extension
            stem, suffix = base.stem, base.suffix
            output_path = base.with_name(f"{stem}_decrypted{suffix}")
        else:
            stem, suffix = input_path.stem, input_path.suffix
            output_path = input_path.with_name(f"{stem}_decrypted{suffix}")

        try:
            decrypt_file(str(input_path), str(output_path), password)
            self.log(f"[Decrypt] Decrypted '{input_path}' -> '{output_path}'.")
            messagebox.showinfo("Success", f"File decrypted to:\n{output_path}")
        except Exception as e:
            self.log(f"[Error] Decryption failed: {e}")
            messagebox.showerror("Error", f"Decryption failed:\n{e}")


def main() -> None:
    root = tk.Tk()
    app = App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
