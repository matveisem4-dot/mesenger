"""
SecureMessenger Desktop Client
Собирается в EXE через GitHub Actions
"""
import webview
import sys
import os

SERVER = os.environ.get('SM_SERVER', 'http://localhost:5000')
TITLE  = 'SecureMessenger'

if __name__ == '__main__':
    if len(sys.argv) > 1:
        SERVER = sys.argv[1]

    window = webview.create_window(
        TITLE, SERVER,
        width=1100, height=750,
        min_size=(400, 500),
        confirm_close=True,
        text_select=True
    )
    webview.start(debug=False)
