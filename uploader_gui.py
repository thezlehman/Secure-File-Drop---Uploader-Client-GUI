#!/usr/bin/env python3
"""
Secure File Drop / Uploader Client GUI

Demo client to upload files to an HTTPS endpoint with optional
API key / Bearer token. Uses multipart/form-data POST.

This is intended as a portfolio/demo app, not a production uploader.
"""

import os
import ssl
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib.parse import urlparse
import mimetypes
import threading


class UploaderGUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Secure File Drop / Uploader Client")
        self.root.geometry("720x520")
        self.root.minsize(640, 420)

        self.upload_url_var = tk.StringVar(value="https://httpbin.org/post")
        self.auth_header_var = tk.StringVar()
        self.auth_type_var = tk.StringVar(value="Bearer")
        self.file_paths_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready")
        self.abort_flag = False

        self.create_widgets()

    def create_widgets(self) -> None:
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=tk.NSEW)
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)

        ttk.Label(
            main_frame,
            text="Secure File Drop / Uploader Client",
            font=("Arial", 14, "bold"),
        ).grid(row=0, column=0, sticky=tk.W, pady=(0, 8))

        # URL
        url_frame = ttk.LabelFrame(main_frame, text="Upload endpoint", padding="8")
        url_frame.grid(row=1, column=0, sticky=tk.EW, pady=4)
        url_frame.columnconfigure(1, weight=1)
        ttk.Label(url_frame, text="URL:", width=12).grid(row=0, column=0, sticky=tk.W, pady=3)
        ttk.Entry(url_frame, textvariable=self.upload_url_var).grid(
            row=0, column=1, sticky=tk.EW, pady=3, padx=(0, 4)
        )

        # Auth (optional)
        auth_frame = ttk.LabelFrame(main_frame, text="Authentication (optional)", padding="8")
        auth_frame.grid(row=2, column=0, sticky=tk.EW, pady=4)
        auth_frame.columnconfigure(1, weight=1)
        ttk.Label(auth_frame, text="Type:", width=12).grid(row=0, column=0, sticky=tk.W, pady=3)
        auth_combo = ttk.Combobox(
            auth_frame,
            textvariable=self.auth_type_var,
            values=["Bearer", "X-API-Key", "Authorization"],
            width=18,
            state="readonly",
        )
        auth_combo.grid(row=0, column=1, sticky=tk.W, pady=3, padx=(0, 4))
        ttk.Label(auth_frame, text="Token/Key:", width=12).grid(row=1, column=0, sticky=tk.W, pady=3)
        ttk.Entry(auth_frame, textvariable=self.auth_header_var, show="*").grid(
            row=1, column=1, sticky=tk.EW, pady=3, padx=(0, 4)
        )

        # Files
        file_frame = ttk.LabelFrame(main_frame, text="Files to upload", padding="8")
        file_frame.grid(row=3, column=0, sticky=tk.EW, pady=4)
        file_frame.columnconfigure(0, weight=1)
        ttk.Entry(file_frame, textvariable=self.file_paths_var, state="readonly").grid(
            row=0, column=0, sticky=tk.EW, pady=3, padx=(0, 4)
        )
        btn_frame = ttk.Frame(file_frame)
        btn_frame.grid(row=0, column=1, sticky=tk.W)
        ttk.Button(btn_frame, text="Add files...", command=self.add_files, width=12).pack(
            side=tk.LEFT, padx=2
        )
        ttk.Button(btn_frame, text="Clear", command=self.clear_files, width=8).pack(
            side=tk.LEFT, padx=2
        )

        # Log
        log_frame = ttk.LabelFrame(main_frame, text="Log", padding="8")
        log_frame.grid(row=4, column=0, sticky=tk.NSEW, pady=4)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(4, weight=1)
        self.log_text = scrolledtext.ScrolledText(
            log_frame, height=12, wrap=tk.WORD, font=("Consolas", 9)
        )
        self.log_text.grid(row=0, column=0, sticky=tk.NSEW)

        # Buttons
        btn_row = ttk.Frame(main_frame)
        btn_row.grid(row=5, column=0, sticky=tk.EW, pady=8)
        ttk.Button(
            btn_row,
            text="Upload",
            command=self.start_upload,
            width=14,
        ).pack(side=tk.LEFT, padx=4)
        ttk.Label(btn_row, textvariable=self.status_var, relief=tk.SUNKEN).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=8
        )

    def log(self, msg: str) -> None:
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()

    def add_files(self) -> None:
        paths = filedialog.askopenfilenames(title="Select files to upload")
        if paths:
            current = self.file_paths_var.get().strip()
            new_list = ", ".join(paths) if isinstance(paths, (list, tuple)) else paths
            self.file_paths_var.set(new_list if not current else current + "; " + new_list)

    def clear_files(self) -> None:
        self.file_paths_var.set("")

    def _parse_file_list(self) -> list[str]:
        raw = self.file_paths_var.get().strip()
        if not raw:
            return []
        return [p.strip() for p in raw.replace(",", ";").split(";") if p.strip()]

    def _upload_worker(self) -> None:
        url = self.upload_url_var.get().strip()
        if not url:
            self.root.after(0, lambda: messagebox.showerror("Error", "Please enter upload URL."))
            return
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                self.root.after(
                    0,
                    lambda: messagebox.showerror(
                        "Error", "URL must use http or https."
                    ),
                )
                return
        except Exception:
            self.root.after(0, lambda: messagebox.showerror("Error", "Invalid URL."))
            return

        paths = self._parse_file_list()
        if not paths:
            self.root.after(
                0,
                lambda: messagebox.showerror("Error", "Please add at least one file."),
            )
            return

        self.root.after(0, lambda: self.status_var.set("Uploading..."))
        self.root.after(0, lambda: self.log(f"Uploading {len(paths)} file(s) to {url}"))

        boundary = "----PythonSecureFileDropBoundary"
        body_parts = []

        for path in paths:
            if self.abort_flag:
                break
            if not os.path.isfile(path):
                self.root.after(0, lambda p=path: self.log(f"Skip (not file): {p}"))
                continue
            name = os.path.basename(path)
            mime, _ = mimetypes.guess_type(path)
            mime = mime or "application/octet-stream"
            with open(path, "rb") as f:
                data = f.read()
            header = (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; filename="{name}"\r\n'
                f"Content-Type: {mime}\r\n\r\n"
            ).encode("utf-8")
            body_parts.append(header + data + b"\r\n")

        if not body_parts:
            self.root.after(0, lambda: self.status_var.set("No valid files."))
            return

        body = b"".join(body_parts)
        body += f"--{boundary}--\r\n".encode("utf-8")

        headers = {
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(len(body)),
        }
        auth_type = self.auth_type_var.get().strip()
        auth_value = self.auth_header_var.get().strip()
        if auth_value:
            if auth_type == "Bearer":
                headers["Authorization"] = f"Bearer {auth_value}"
            elif auth_type == "X-API-Key":
                headers["X-API-Key"] = auth_value
            else:
                headers["Authorization"] = auth_value

        req = Request(url, data=body, headers=headers, method="POST")
        ctx = ssl.create_default_context()

        try:
            with urlopen(req, timeout=60, context=ctx) as resp:
                code = resp.getcode()
                content = resp.read().decode("utf-8", errors="replace")[:2000]
                def ok():
                    self.log(f"Response {code}")
                    self.log(content)
                    self.status_var.set(f"Done. HTTP {code}")
                self.root.after(0, ok)
        except HTTPError as e:
            def err_http():
                self.log(f"HTTP error: {e.code} {e.reason}")
                self.status_var.set(f"Error HTTP {e.code}")
            self.root.after(0, err_http)
        except URLError as e:
            def err_url():
                self.log(f"URL error: {e.reason}")
                self.status_var.set("Upload failed.")
            self.root.after(0, err_url)
        except Exception as e:
            def err_ex():
                self.log(str(e))
                self.status_var.set("Upload failed.")
            self.root.after(0, err_ex)

    def start_upload(self) -> None:
        self.abort_flag = False
        threading.Thread(target=self._upload_worker, daemon=True).start()


def main() -> None:
    root = tk.Tk()
    UploaderGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
