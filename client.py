import webview
import sys

SERVER = "https://tune-michelle-mia-charles.trycloudflare.com/"

if len(sys.argv) > 1:
    SERVER = sys.argv[1]

if __name__ == '__main__':
    webview.create_window('SecureMessenger', SERVER, width=1100, height=750)
    webview.start()
