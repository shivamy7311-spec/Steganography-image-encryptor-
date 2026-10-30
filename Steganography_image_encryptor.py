import os
import struct
import numpy as np
from PIL import Image
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import base64

# --- Mathematical & Protocol Constants ---
SENTINEL = b"STEG1001"            # 8-byte frame identifier
HEADER_FMT = ">8sI"                # 8 bytes sentinel + 4 bytes payload length (big-endian)
HEADER_SIZE = struct.calcsize(HEADER_FMT)  # 12 bytes total (96 bits)
SALT_SIZE = 16                     # 128-bit random salt for PBKDF2
PBKDF2_ITERATIONS = 100_000        # Standard iteration count for key derivation


def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derives a url-safe base64 256-bit encryption key using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


def encrypt_payload(plaintext: str, passphrase: str) -> bytes:
    """Encrypts plaintext message using AES-128-CBC + HMAC via Fernet token."""
    salt = os.urandom(SALT_SIZE)
    key = derive_key(passphrase, salt)
    fernet = Fernet(key)
    ciphertext = fernet.encrypt(plaintext.encode("utf-8"))
    # Prepend the 16-byte random salt so recipient can derive the matching key
    return salt + ciphertext


def decrypt_payload(raw_payload: bytes, passphrase: str) -> str:
    """Extracts salt, derives key, and performs AES-CBC decryption & HMAC verification."""
    if len(raw_payload) <= SALT_SIZE:
        raise ValueError("Extracted payload size is invalid or corrupted.")
    salt = raw_payload[:SALT_SIZE]
    ciphertext = raw_payload[SALT_SIZE:]
    key = derive_key(passphrase, salt)
    fernet = Fernet(key)
    return fernet.decrypt(ciphertext).decode("utf-8")


def bytes_to_bits(data: bytes) -> np.ndarray:
    """Converts a bytes object into a 1D NumPy array of binary bits."""
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8))


def bits_to_bytes(bits: np.ndarray) -> bytes:
    """Converts a 1D NumPy array of binary bits back into bytes."""
    return np.packbits(bits).tobytes()


def embed_data(cover_path: str, output_path: str, plaintext: str, passphrase: str):
    """Embeds header and encrypted ciphertext into cover image using 1-bit LSB substitution."""
    encrypted_payload = encrypt_payload(plaintext, passphrase)
    payload_len = len(encrypted_payload)
    header = struct.pack(HEADER_FMT, SENTINEL, payload_len)
    full_data = header + encrypted_payload
    bits = bytes_to_bits(full_data)
    total_bits = len(bits)

    img = Image.open(cover_path).convert("RGB")
    arr = np.array(img, dtype=np.uint8)
    flat = arr.flatten()

    if total_bits > flat.size:
        raise ValueError(
            f"Payload capacity exceeded. Required: {total_bits} bits ({total_bits // 8} bytes), "
            f"Available: {flat.size} bits ({flat.size // 8} bytes)."
        )

    # 1-bit LSB substitution: P'_v = (P_v & 0xFE) | b
    flat[:total_bits] = (flat[:total_bits] & 0xFE) | bits
    stego_arr = flat.reshape(arr.shape)

    stego_img = Image.fromarray(stego_arr, mode="RGB")
    stego_img.save(output_path, format="PNG")


def extract_data(stego_path: str, passphrase: str) -> str:
    """Extracts and verifies header, reads payload bits, and decrypts message."""
    img = Image.open(stego_path).convert("RGB")
    flat = np.array(img, dtype=np.uint8).flatten()

    header_bits_len = HEADER_SIZE * 8
    if flat.size < header_bits_len:
        raise ValueError("Image dimensions too small to contain metadata header.")

    # Extract least significant bits (b0 = P'_v & 0x01)
    extracted_header_bits = flat[:header_bits_len] & 0x01
    header_bytes = bits_to_bytes(extracted_header_bits)

    sentinel, payload_len = struct.unpack(HEADER_FMT, header_bytes)
    if sentinel != SENTINEL:
        raise ValueError("Invalid carrier: No 'STEG1001' sentinel frame found.")

    total_payload_bits = payload_len * 8
    total_required_bits = header_bits_len + total_payload_bits
    if flat.size < total_required_bits:
        raise ValueError("Image corrupted: Incomplete payload length specified in header.")

    extracted_payload_bits = flat[header_bits_len:total_required_bits] & 0x01
    raw_payload = bits_to_bytes(extracted_payload_bits)

    return decrypt_payload(raw_payload, passphrase)


# --- Desktop Graphical Interface ---
class SteganographyApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("STEGANOGRAPHY IMAGE ENCRYPTOR")
        self.geometry("720x540")
        self.resizable(False, False)
        self.configure(bg="#2d3748")  # Slate dark background

        self.mode_var = tk.StringVar(value="embed")
        self.file_path_var = tk.StringVar()
        self.pass_var = tk.StringVar()

        self._apply_styles()
        self._build_ui()

    def _apply_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(".", background="#2d3748", foreground="#e2e8f0", font=("Segoe UI", 10))
        style.configure("TLabel", background="#2d3748", foreground="#e2e8f0", font=("Segoe UI", 10))
        style.configure("Header.TLabel", font=("Segoe UI", 13, "bold"), foreground="#63b3ed")
        style.configure("TRadiobutton", background="#2d3748", foreground="#e2e8f0", font=("Segoe UI", 10, "bold"))
        style.configure("Action.TButton", font=("Segoe UI", 10, "bold"), background="#319795", foreground="#ffffff")
        style.map("Action.TButton", background=[("active", "#285e61")])

    def _build_ui(self):
        container = tk.Frame(self, bg="#2d3748", padx=20, pady=15)
        container.pack(fill=tk.BOTH, expand=True)

        # Title
        tk.Label(
            container,
            text="STEGANOGRAPHY IMAGE ENCRYPTOR",
            font=("Segoe UI", 14, "bold"),
            bg="#2d3748",
            fg="#63b3ed",
        ).pack(anchor="w", pady=(0, 10))

        # Mode Selection
        mode_frame = tk.LabelFrame(
            container, text=" Operation Mode ", bg="#1a202c", fg="#a0aec0", padx=10, pady=8
        )
        mode_frame.pack(fill=tk.X, pady=(0, 12))

        ttk.Radiobutton(
            mode_frame,
            text="Embed Payload",
            variable=self.mode_var,
            value="embed",
            command=self._on_mode_change,
        ).pack(side=tk.LEFT, padx=15)
        ttk.Radiobutton(
            mode_frame,
            text="Extract Payload",
            variable=self.mode_var,
            value="extract",
            command=self._on_mode_change,
        ).pack(side=tk.LEFT, padx=15)

        # File Selection
        self.file_label = ttk.Label(container, text="1. Select Cover Image File (PNG recommended):")
        self.file_label.pack(anchor="w", pady=(4, 2))

        file_frame = tk.Frame(container, bg="#2d3748")
        file_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Entry(file_frame, textvariable=self.file_path_var, font=("Segoe UI", 10)).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8)
        )
        ttk.Button(file_frame, text="Browse...", command=self._browse_file).pack(side=tk.RIGHT)

        # Secret Message Area
        self.msg_label = ttk.Label(container, text="2. Enter Secret Message:")
        self.msg_label.pack(anchor="w", pady=(4, 2))

        self.text_area = tk.Text(
            container,
            height=5,
            bg="#1a202c",
            fg="#edf2f7",
            insertbackground="#edf2f7",
            font=("Consolas", 10),
            padx=8,
            pady=6,
            relief=tk.FLAT,
        )
        self.text_area.pack(fill=tk.X, pady=(0, 10))

        # Passphrase Field
        ttk.Label(container, text="3. Secret Encryption Passphrase:").pack(anchor="w", pady=(4, 2))
        ttk.Entry(container, textvariable=self.pass_var, show="*", font=("Segoe UI", 10)).pack(
            fill=tk.X, pady=(0, 14)
        )

        # Action Button
        self.action_btn = ttk.Button(
            container,
            text="EXECUTE LSB EMBEDDING PROCESS",
            style="Action.TButton",
            command=self._run_process,
        )
        self.action_btn.pack(fill=tk.X, ipady=6, pady=(0, 12))

        # Status Bar
        self.status_bar = tk.Label(
            container,
            text="Status: Ready",
            bg="#1a202c",
            fg="#a0aec0",
            anchor="w",
            padx=10,
            pady=6,
            font=("Consolas", 9),
        )
        self.status_bar.pack(fill=tk.X)

    def _on_mode_change(self):
        if self.mode_var.get() == "embed":
            self.file_label.config(text="1. Select Cover Image File (PNG recommended):")
            self.msg_label.config(text="2. Enter Secret Message:")
            self.action_btn.config(text="EXECUTE LSB EMBEDDING PROCESS")
            self.text_area.config(state=tk.NORMAL)
            self.text_area.delete("1.0", tk.END)
        else:
            self.file_label.config(text="1. Select Stego Image File:")
            self.msg_label.config(text="2. Extracted Decrypted Message Output:")
            self.action_btn.config(text="EXECUTE LSB EXTRACTION PROCESS")
            self.text_area.delete("1.0", tk.END)

    def _browse_file(self):
        path = filedialog.askopenfilename(
            filetypes=[("Image Files", "*.png *.bmp *.tiff *.jpg *.jpeg"), ("All Files", "*.*")]
        )
        if path:
            self.file_path_var.set(path)

    def _run_process(self):
        img_path = self.file_path_var.get().strip()
        passphrase = self.pass_var.get().strip()

        if not os.path.exists(img_path):
            messagebox.showerror("Error", "Selected image path does not exist.")
            return

        if not passphrase:
            messagebox.showerror("Error", "Please enter a secret encryption passphrase.")
            return

        if self.mode_var.get() == "embed":
            msg = self.text_area.get("1.0", tk.END).strip()
            if not msg:
                messagebox.showerror("Error", "Please provide a secret message to embed.")
                return

            out_path = filedialog.asksaveasfilename(
                defaultextension=".png",
                filetypes=[("PNG Image", "*.png")],
                title="Save Stego Image As",
            )
            if not out_path:
                return

            try:
                embed_data(img_path, out_path, msg, passphrase)
                self.status_bar.config(
                    text=f"[SUCCESS] Stego Image saved to {os.path.basename(out_path)}",
                    fg="#48bb78",
                )
                messagebox.showinfo("Success", f"Payload embedded and saved to:\n{out_path}")
            except Exception as e:
                self.status_bar.config(text=f"[ERROR] {str(e)}", fg="#f56565")
                messagebox.showerror("Embedding Error", str(e))

        else:
            try:
                decrypted_msg = extract_data(img_path, passphrase)
                self.text_area.config(state=tk.NORMAL)
                self.text_area.delete("1.0", tk.END)
                self.text_area.insert("1.0", decrypted_msg)
                self.status_bar.config(
                    text="[SUCCESS] Payload extracted and verified successfully.",
                    fg="#48bb78",
                )
                messagebox.showinfo("Success", "Decryption & authentication successful.")
            except Exception as e:
                self.status_bar.config(text=f"[FAILED] {str(e)}", fg="#f56565")
                messagebox.showerror(
                    "Extraction Error",
                    "Failed to extract or decrypt message.\nEnsure the passphrase is correct and the image contains valid stego data.",
                )


if __name__ == "__main__":
    app = SteganographyApp()
    app.mainloop()
