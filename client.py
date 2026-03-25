import webview
import json
import os

CONFIG = os.path.join(os.path.expanduser("~"), ".securemessenger.json")

def load_url():
    try:
        with open(CONFIG, "r") as f:
            return json.load(f).get("url", "")
    except:
        return ""

def save_url(url):
    with open(CONFIG, "w") as f:
        json.dump({"url": url}, f)

class App:
    def __init__(self):
        self.window = None

    def connect(self, url):
        url = url.strip()
        if not url.startswith("http"):
            url = "https://" + url
        save_url(url)
        self.window.load_url(url)

    def get_saved_url(self):
        return load_url()

if __name__ == '__main__':
    app = App()
    saved = load_url()

    html = """
    <!DOCTYPE html>
    <html>
    <head><meta charset="utf-8">
    <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:sans-serif;background:#0a0a0f;color:#e0e0e0;
    display:flex;align-items:center;justify-content:center;height:100vh}
    .card{background:#12121a;border-radius:20px;padding:40px;
    width:400px;border:1px solid #1e1e30;text-align:center}
    h1{color:#0df;margin-bottom:10px;font-size:22px}
    p{color:#888;font-size:13px;margin-bottom:20px}
    input{width:100%;padding:14px;background:#1a1a2e;border:1px solid #1e1e30;
    border-radius:8px;color:#e0e0e0;font-size:14px;outline:none;margin-bottom:15px}
    input:focus{border-color:#0df}
    button{width:100%;padding:14px;border:none;border-radius:8px;
    background:linear-gradient(135deg,#0df,#09c);color:#000;
    font-size:15px;font-weight:bold;cursor:pointer}
    button:hover{opacity:0.9}
    .hint{color:#555;font-size:11px;margin-top:15px}
    </style></head>
    <body>
    <div class="card">
    <div style="font-size:48px;margin-bottom:10px">🔐</div>
    <h1>SecureMessenger</h1>
    <p>Введите URL сервера из логов GitHub Actions</p>
    <input id="url" placeholder="https://xxxx.trycloudflare.com"
           value="{SAVED}" autofocus
           onkeypress="if(event.key==='Enter')go()">
    <button onclick="go()">Подключиться</button>
    <p class="hint">URL находится в Actions → Server 24/7 → логи</p>
    </div>
    <script>
    function go(){
        var url = document.getElementById('url').value.trim();
        if(url) pywebview.api.connect(url);
    }
    </script>
    </body></html>
    """.replace("{SAVED}", saved)

    app.window = webview.create_window(
        'SecureMessenger',
        html=html,
        width=500,
        height=450,
        js_api=app
    )
    webview.start()
