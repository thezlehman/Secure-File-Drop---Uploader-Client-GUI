# Secure File Drop / Uploader Client GUI

Demo client to upload files to an HTTPS endpoint with optional authentication (Bearer token or API key).

## Features

- **Upload URL** – Any `http` or `https` endpoint that accepts `multipart/form-data` POST.
- **Authentication (optional)** – Bearer token, X-API-Key, or custom Authorization header.
- **Multiple files** – Add one or more files; each is sent as a form field named `file`.
- **Log** – Shows request result and response body snippet.

## Requirements

- Windows 10/11 (or any OS with Python + tkinter)
- Python 3.6+ (tkinter, urllib, ssl – standard library only)

## Running

From this folder:

```bash
python uploader_gui.py
```

Or on Windows, double-click `run_uploader.bat`.

## Notes

- Default URL is `https://httpbin.org/post` for quick testing; replace with your own endpoint.
- This is a demo/portfolio app. For production use, consider retries, progress bars, and proper certificate validation.
