#!/usr/bin/env python3
"""SecureMessenger Server — AES-256 + 2FA + WebRTC Calls"""
import os,sys,time,json,hmac,hashlib,secrets,string,sqlite3,smtplib,ssl
import threading,functools,base64,logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from contextlib import contextmanager
from flask import Flask,render_template_string,request,redirect,session,jsonify
from flask_socketio import SocketIO,emit,join_room,leave_room,disconnect
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import bcrypt

# ─── Config ───
SK=os.environ.get('SK',secrets.token_hex(32))
AK=os.environ.get('AK',secrets.token_hex(32))
DB=os.environ.get('DB','msg.db')
HOST=os.environ.get('H','0.0.0.0')
PORT=int(os.environ.get('P',5000))
SH=os.environ.get('SH','smtp.gmail.com')
SP=int(os.environ.get('SP',587))
SE=os.environ.get('SE','')
SX=os.environ.get('SX','')
ICE=[{'urls':'stun:stun.l.google.com:19302'},{'urls':'stun:stun1.l.google.com:19302'}]

logging.basicConfig(level=logging.INFO,format='%(asctime)s [%(levelname)s] %(message)s')
log=logging.getLogger('SM')
app=Flask(__name__);app.secret_key=SK
sio=SocketIO(app,cors_allowed_origins="*",async_mode='threading')
ON={};SM={};AC={}  # online, sid_map, active_calls
TD={}  # trusted_devices

# ─── Crypto (зашифровано при обфускации) ───
class C:
    def __init__(s,mk):
        s._m=mk.encode()if isinstance(mk,str)else mk
        s._f=Fernet(base64.urlsafe_b64encode(s._d(b'f',32)))
        s._s=s._d(b's',32)
    def _d(s,ctx,ln):
        return PBKDF2HMAC(algorithm=hashes.SHA256(),length=ln,salt=ctx,
            iterations=100000,backend=default_backend()).derive(s._m)
    def e(s,t):
        k=s._d(b'a',32);n=os.urandom(12)
        ci=Cipher(algorithms.AES(k),modes.GCM(n),backend=default_backend())
        en=ci.encryptor();ct=en.update(t.encode())+en.finalize()
        return base64.urlsafe_b64encode(n+en.tag+ct).decode()
    def de(s,d):
        k=s._d(b'a',32);r=base64.urlsafe_b64decode(d)
        ci=Cipher(algorithms.AES(k),modes.GCM(r[:12],r[12:28]),backend=default_backend())
        dc=ci.decryptor();return(dc.update(r[28:])+dc.finalize()).decode()
    def ef(s,d):return s._f.encrypt(d.encode()).decode()
    def df(s,t):return s._f.decrypt(t.encode()).decode()
    @staticmethod
    def hp(p):return bcrypt.hashpw(p.encode(),bcrypt.gensalt(12)).decode()
    @staticmethod
    def cp(p,h):return bcrypt.checkpw(p.encode(),h.encode())
cr=C(AK)

# ─── ID Generator ───
_AB='ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
def gid():return'SM-'+''.join(secrets.choice(_AB)for _ in range(8))
def gpw():
    c=string.ascii_letters+string.digits+"!@#$%&"
    while True:
        p=''.join(secrets.choice(c)for _ in range(14))
        if any(x.isupper()for x in p)and any(x.islower()for x in p)and any(x.isdigit()for x in p):return p
def g2f():return''.join(secrets.choice(string.digits)for _ in range(6))
def gcid():return f"C-{secrets.token_hex(6).upper()}"
def gsid():return hashlib.sha256(f"{time.time()}{secrets.token_hex(16)}".encode()).hexdigest()

# ─── Email (SMTP, без API) ───
def send_code(to,code,uid):
    if not SE or not SX:
        print(f"\n{'='*40}\n📧 2FA: {code} | ID: {uid}\n{'='*40}\n");return True
    try:
        m=MIMEMultipart('alternative');m['From']=f"SM <{SE}>";m['To']=to;m['Subject']=f"Код: {code}"
        h=f"""<div style="font-family:sans-serif;background:#111;color:#eee;padding:30px;
        border-radius:12px;text-align:center;max-width:400px;margin:auto">
        <h2 style="color:#0df">🔐 SecureMessenger</h2>
        <div style="font-size:36px;letter-spacing:8px;color:#0df;background:#1a1a2e;
        padding:20px;border-radius:8px;margin:15px 0;font-family:monospace">{code}</div>
        <p style="color:#555;font-size:12px">{uid} • 5 мин</p></div>"""
        m.attach(MIMEText(h,'html','utf-8'))
        s=smtplib.SMTP(SH,SP,timeout=30);s.starttls(context=ssl.create_default_context())
        s.login(SE,SX);s.sendmail(SE,to,m.as_string());s.quit();return True
    except Exception as ex:
        log.error(f"Email: {ex}");print(f"\n📧 2FA: {code}\n");return True

# ─── Database ───
class D:
    def __init__(s,p):
        s.p=p;s._l=threading.local();s._init()
    def _c(s):
        if not hasattr(s._l,'c')or not s._l.c:
            s._l.c=sqlite3.connect(s.p,check_same_thread=False)
            s._l.c.row_factory=sqlite3.Row;s._l.c.execute("PRAGMA journal_mode=WAL")
        return s._l.c
    @contextmanager
    def _t(s):
        c=s._c()
        try:yield c;c.commit()
        except:c.rollback();raise
    def _init(s):
        with s._t()as c:c.executescript("""
        CREATE TABLE IF NOT EXISTS u(id TEXT PRIMARY KEY,pw TEXT,email TEXT,name TEXT,
        status TEXT DEFAULT'offline',ts REAL,tfa INTEGER DEFAULT 1);
        CREATE TABLE IF NOT EXISTS codes(id INTEGER PRIMARY KEY,uid TEXT,h TEXT,exp REAL,used INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS sess(sid TEXT PRIMARY KEY,uid TEXT,tok TEXT,active INTEGER DEFAULT 1);
        CREATE TABLE IF NOT EXISTS msg(id INTEGER PRIMARY KEY,s TEXT,r TEXT,ct TEXT,ts REAL,rd INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS ct(uid TEXT,cid TEXT,PRIMARY KEY(uid,cid));
        CREATE TABLE IF NOT EXISTS calls(id TEXT PRIMARY KEY,ca TEXT,re TEXT,tp TEXT,st TEXT,ts REAL,dur INTEGER DEFAULT 0);
        CREATE INDEX IF NOT EXISTS ix1 ON msg(s,ts);CREATE INDEX IF NOT EXISTS ix2 ON msg(r,ts);""")
    def add_user(s,uid,pw,em,nm):
        try:
            with s._t()as c:c.execute("INSERT INTO u VALUES(?,?,?,?,?,?,?)",(uid,pw,em,nm,'offline',time.time(),1));return True
        except:return False
    def get_user(s,uid):
        r=s._c().execute("SELECT*FROM u WHERE id=?",(uid,)).fetchone()
        if not r:return None
        try:return{'id':r['id'],'pw':r['pw'],'email':cr.de(r['email']),'name':cr.de(r['name']),'status':r['status'],'tfa':r['tfa']}
        except:return None
    def exists(s,uid):return s._c().execute("SELECT 1 FROM u WHERE id=?",(uid,)).fetchone()is not None
    def find_email(s,em):
        for r in s._c().execute("SELECT id,email FROM u").fetchall():
            try:
                if cr.de(r['email'])==em:return s.get_user(r['id'])
            except:pass
        return None
    def set_st(s,uid,st):
        with s._t()as c:c.execute("UPDATE u SET status=? WHERE id=?",(st,uid))
    def save_code(s,uid,h,exp=300):
        with s._t()as c:c.execute("DELETE FROM codes WHERE uid=?",(uid,));c.execute("INSERT INTO codes(uid,h,exp)VALUES(?,?,?)",(uid,h,time.time()+exp))
    def chk_code(s,uid,h):
        r=s._c().execute("SELECT id FROM codes WHERE uid=? AND h=? AND used=0 AND exp>?",(uid,h,time.time())).fetchone()
        if r:
            with s._t()as c:c.execute("UPDATE codes SET used=1 WHERE id=?",(r['id'],));return True
        return False
    def mk_sess(s,sid,uid,tok):
        with s._t()as c:
            n=c.execute("SELECT COUNT(*)as n FROM sess WHERE uid=? AND active=1",(uid,)).fetchone()['n']
            if n>=5:c.execute("DELETE FROM sess WHERE sid=(SELECT sid FROM sess WHERE uid=? AND active=1 ORDER BY rowid LIMIT 1)",(uid,))
            c.execute("INSERT OR REPLACE INTO sess VALUES(?,?,?,1)",(sid,uid,tok))
    def get_sess(s,sid):
        r=s._c().execute("SELECT*FROM sess WHERE sid=? AND active=1",(sid,)).fetchone()
        return dict(r)if r else None
    def del_sess(s,sid):
        with s._t()as c:c.execute("UPDATE sess SET active=0 WHERE sid=?",(sid,))
    def save_msg(s,se,re,ct):
        with s._t()as c:return c.execute("INSERT INTO msg(s,r,ct,ts)VALUES(?,?,?,?)",(se,re,cr.e(ct),time.time())).lastrowid
    def get_msgs(s,a,b,lim=50):
        rows=s._c().execute("SELECT*FROM msg WHERE(s=? AND r=?)OR(s=? AND r=?)ORDER BY ts DESC LIMIT?",(a,b,b,a,lim)).fetchall()
        ms=[]
        for r in rows:
            try:ms.append({'id':r['id'],'sender':r['s'],'receiver':r['r'],'content':cr.de(r['ct']),'ts':r['ts'],'read':r['rd']})
            except:pass
        ms.reverse();return ms
    def mark_rd(s,rd,se):
        with s._t()as c:c.execute("UPDATE msg SET rd=1 WHERE r=? AND s=? AND rd=0",(rd,se))
    def unread(s,uid):
        return{r['s']:r['n']for r in s._c().execute("SELECT s,COUNT(*)as n FROM msg WHERE r=? AND rd=0 GROUP BY s",(uid,)).fetchall()}
    def add_ct(s,uid,cid):
        with s._t()as c:c.execute("INSERT OR REPLACE INTO ct VALUES(?,?)",(uid,cid))
    def get_cts(s,uid):
        rows=s._c().execute("SELECT ct.cid,u.status,u.name FROM ct JOIN u ON ct.cid=u.id WHERE ct.uid=?",(uid,)).fetchall()
        cs=[]
        for r in rows:
            try:cs.append({'id':r['cid'],'name':cr.de(r['name']),'status':r['status']})
            except:cs.append({'id':r['cid'],'name':r['cid'],'status':r['status']})
        return cs
    def save_call(s,cid,ca,re,tp):
        with s._t()as c:c.execute("INSERT INTO calls VALUES(?,?,?,?,?,?,0)",(cid,ca,re,tp,'ring',time.time()))
    def end_call(s,cid,st,dur=0):
        with s._t()as c:c.execute("UPDATE calls SET st=?,dur=? WHERE id=?",(st,dur,cid))
db=D(DB)

# ─── Auth ───
def me(e):
    p=e.split('@');d=p[1].split('.')if len(p)==2 else['***']
    return f"{p[0][0]}***@{d[0][0]}***.{'.'.join(d[1:])}"if len(p)==2 else'***'

def reg(email,name,pw=None):
    if db.find_email(email):return{'ok':0,'err':'Email занят'}
    uid=gid()
    while db.exists(uid):uid=gid()
    pw=pw if pw and len(pw)>=8 else gpw()
    if db.add_user(uid,cr.hp(pw),cr.e(email),cr.e(name)):return{'ok':1,'uid':uid,'pw':pw}
    return{'ok':0,'err':'Ошибка'}

def login1(uid,pw,dev='',ip=''):
    u=db.get_user(uid)
    if not u or not cr.cp(pw,u['pw']):return{'ok':0,'err':'Неверный ID/пароль'}
    dh=hashlib.sha256(f"{uid}:{dev}:{ip}".encode()).hexdigest()
    if u['tfa']:
        tr=TD.get(uid,{})
        if dh in tr and time.time()-tr[dh]<30*86400:return _mks(uid)
        code=g2f();db.save_code(uid,hashlib.sha256(code.encode()).hexdigest())
        threading.Thread(target=send_code,args=(u['email'],code,uid),daemon=True).start()
        return{'ok':1,'2fa':1,'uid':uid,'hint':me(u['email'])}
    return _mks(uid)

def login2(uid,code,dev='',ip=''):
    if db.chk_code(uid,hashlib.sha256(code.encode()).hexdigest()):
        dh=hashlib.sha256(f"{uid}:{dev}:{ip}".encode()).hexdigest()
        TD.setdefault(uid,{})[dh]=time.time();return _mks(uid)
    return{'ok':0,'err':'Неверный код'}

def _mks(uid):
    sid=gsid();tok=cr.ef(json.dumps({'u':uid,'t':time.time(),'n':secrets.token_hex(8)}))
    db.mk_sess(sid,uid,tok);db.set_st(uid,'online');return{'ok':1,'2fa':0,'sid':sid,'uid':uid}

def chks(sid):
    s=db.get_sess(sid)
    if not s:return None
    try:
        d=json.loads(cr.df(s['tok']))
        if time.time()-d['t']>86400:db.del_sess(sid);return None
        return d['u']
    except:db.del_sess(sid);return None

def lreq(f):
    @functools.wraps(f)
    def w(*a,**k):
        sid=session.get('sid')
        if not sid:return redirect('/login')
        uid=chks(sid)
        if not uid:session.clear();return redirect('/login')
        return f(uid=uid,*a,**k)
    return w

def aauth(f):
    @functools.wraps(f)
    def w(*a,**k):
        sid=request.headers.get('X-S')or session.get('sid')
        if not sid:return jsonify({'e':1}),401
        uid=chks(sid)
        if not uid:return jsonify({'e':1}),401
        return f(uid=uid,*a,**k)
    return w

# ─── HTML/CSS/JS (компактно) ───
CSS="""*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,sans-serif;
background:#0a0a0f;color:#e0e0e0;overflow:hidden;height:100vh}
.ac{display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}
.cd{background:#12121a;border-radius:20px;padding:40px;width:100%;max-width:440px;border:1px solid #1e1e30}
.cd h1{text-align:center;color:#0df;margin-bottom:5px}
.cd .sub{text-align:center;color:#888;font-size:14px;margin-bottom:25px}
.fg{margin-bottom:18px}.fg label{display:block;margin-bottom:5px;font-size:13px;color:#888}
.fg input{width:100%;padding:13px;background:#1a1a2e;border:1px solid #1e1e30;border-radius:8px;
color:#e0e0e0;font-size:15px;outline:none}.fg input:focus{border-color:#0df}
.btn{display:block;width:100%;padding:14px;border:none;border-radius:8px;font-size:15px;
font-weight:600;cursor:pointer;background:linear-gradient(135deg,#0df,#09c);color:#000;text-decoration:none;text-align:center}
.btn:hover{box-shadow:0 4px 20px rgba(0,212,255,.3)}.err{background:rgba(233,69,96,.1);
border:1px solid rgba(233,69,96,.3);border-radius:8px;padding:12px;margin-bottom:16px;color:#e94560}
.ft{text-align:center;margin-top:18px;color:#888;font-size:14px}.ft a{color:#0df;text-decoration:none}
.cv{font-family:monospace;font-size:18px;color:#0df;background:#0a0a0f;padding:10px 14px;
border-radius:8px;margin:5px 0;word-break:break-all}
.cp{background:#16213e;border:1px solid #1e1e30;color:#888;padding:5px 10px;border-radius:6px;
cursor:pointer;font-size:12px}.warn{background:rgba(255,167,38,.1);border-radius:8px;padding:12px;
margin:16px 0;color:#ffa726;font-size:14px}
.ci6{text-align:center;font-size:32px!important;letter-spacing:10px;font-family:monospace;font-weight:bold}
.ms{display:flex;height:100vh}.sb{width:320px;background:#12121a;border-right:1px solid #1e1e30;
display:flex;flex-direction:column}.sh{display:flex;align-items:center;justify-content:space-between;
padding:14px;border-bottom:1px solid #1e1e30}.av{width:40px;height:40px;border-radius:50%;
background:#0a4d68;display:flex;align-items:center;justify-content:center;font-weight:bold;
color:#0df;position:relative;flex-shrink:0}.av.on::after{content:'';position:absolute;bottom:0;
right:0;width:12px;height:12px;background:#0e6;border-radius:50%;border:2px solid #12121a}
.ib{background:none;border:none;font-size:20px;cursor:pointer;padding:8px;border-radius:8px}
.ib:hover{background:#16213e}.ss{padding:10px 14px}.ss input{width:100%;padding:10px 14px;
background:#1a1a2e;border:1px solid #1e1e30;border-radius:20px;color:#e0e0e0;font-size:14px;outline:none}
.cl{flex:1;overflow-y:auto}.ci{display:flex;align-items:center;padding:12px 14px;gap:12px;
cursor:pointer;border-bottom:1px solid rgba(255,255,255,.03)}.ci:hover{background:#16213e}
.ci.at{background:#0f3460;border-left:3px solid #0df}.cn{font-size:14px;font-weight:500}
.cs{font-size:12px;color:#555}.ub{background:#0df;color:#000;font-size:11px;font-weight:bold;
min-width:20px;height:20px;border-radius:10px;display:flex;align-items:center;justify-content:center;
padding:0 6px}.ma{flex:1;display:flex;flex-direction:column;background:#0a0a0f;min-width:0}
.ec{display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;color:#555}
.ec .ei{font-size:72px;margin-bottom:20px;opacity:.5}
.mh{display:flex;align-items:center;justify-content:space-between;padding:0 20px;height:60px;
background:#12121a;border-bottom:1px solid #1e1e30}.mc{flex:1;overflow-y:auto;padding:20px}
.ml{display:flex;flex-direction:column;gap:4px}.mg{max-width:70%;padding:10px 14px;border-radius:16px;
font-size:14px;line-height:1.4;word-wrap:break-word;animation:mi .2s ease-out}
@keyframes mi{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
.mg.s{align-self:flex-end;background:#0a4d68;border-bottom-right-radius:4px}
.mg.r{align-self:flex-start;background:#1a1a2e;border-bottom-left-radius:4px}
.mt{font-size:10px;color:#555;margin-top:4px;text-align:right}
.tp{display:flex;align-items:center;gap:8px;padding:8px 0;font-size:13px;color:#555}
.mi{padding:14px 20px;background:#12121a;border-top:1px solid #1e1e30}
.iw{display:flex;align-items:flex-end;gap:10px;background:#1a1a2e;border-radius:24px;
padding:8px 8px 8px 18px;border:1px solid #1e1e30}.iw:focus-within{border-color:#0df}
#inp{flex:1;background:none;border:none;color:#e0e0e0;font-size:15px;resize:none;outline:none;
max-height:120px;line-height:1.4;padding:6px 0;font-family:inherit}
.snb{width:40px;height:40px;border-radius:50%;background:#0df;border:none;color:#000;
cursor:pointer;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.mo{position:fixed;inset:0;background:rgba(0,0,0,.7);display:flex;align-items:center;
justify-content:center;z-index:100}.md{background:#12121a;border-radius:12px;width:90%;
max-width:420px;border:1px solid #1e1e30;padding:20px}
.co{position:fixed;inset:0;background:rgba(0,0,0,.92);display:flex;align-items:center;
justify-content:center;z-index:200}.cc{text-align:center;padding:40px}
.rp{width:120px;height:120px;border-radius:50%;border:2px solid #0df;position:absolute;
animation:rp 2s infinite;opacity:0}@keyframes rp{0%{transform:scale(.8);opacity:.8}100%{transform:scale(2);opacity:0}}
.cab{display:flex;flex-direction:column;align-items:center;gap:8px;background:none;border:none;cursor:pointer}
.cab span{width:64px;height:64px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:28px}
.ct{font-size:36px;font-family:monospace;color:#0df;margin-top:10px}
.vc{position:relative;width:80%;max-width:800px;aspect-ratio:16/9;background:#000;border-radius:12px;
overflow:hidden;margin-bottom:30px}#rv{width:100%;height:100%;object-fit:cover}
.lv{position:absolute;bottom:16px;right:16px;width:160px;aspect-ratio:16/9;border-radius:8px;
border:2px solid #1e1e30;object-fit:cover}
.ccs{display:flex;gap:20px;padding:20px}
.ccb{width:56px;height:56px;border-radius:50%;background:#1a1a2e;border:none;font-size:24px;
cursor:pointer;display:flex;align-items:center;justify-content:center}
.ccb.ec{background:#e94560}.ccb.mu{background:#e94560;opacity:.7}
.nt{position:fixed;top:20px;right:20px;background:#1a1a2e;border:1px solid #1e1e30;border-radius:12px;
padding:14px 18px;z-index:300;animation:si .3s;max-width:340px}
@keyframes si{from{transform:translateX(100%);opacity:0}to{transform:translateX(0);opacity:1}}
@media(max-width:768px){.sb{width:100%;position:absolute;z-index:10}.sb.hd{transform:translateX(-100%)}.mg{max-width:85%}}"""

PL="""<!DOCTYPE html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Вход</title><style>"""+CSS+"""</style></head><body><div class=ac><div class=cd>
<div style="text-align:center;font-size:48px;margin-bottom:10px">🔐</div>
<h1>SecureMessenger</h1><p class=sub>Вход</p>
<form method=POST>{%if e%}<div class=err>❌ {{e}}</div>{%endif%}
<div class=fg><label>ID</label><input name=u placeholder="SM-XXXXXXXX" required style="text-transform:uppercase"></div>
<div class=fg><label>Пароль</label><input type=password name=p required></div>
<button class=btn>🔓 Войти</button></form><div class=ft>Нет аккаунта? <a href=/r>Создать</a></div></div></div></body></html>"""

PR="""<!DOCTYPE html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Регистрация</title><style>"""+CSS+"""</style></head><body><div class=ac><div class=cd>
<div style="text-align:center;font-size:48px;margin-bottom:10px">🔐</div>
<h1>SecureMessenger</h1><p class=sub>Регистрация</p>
{%if ok%}<div style=text-align:center><h2 style="color:#0e6;margin-bottom:16px">✅ Создан!</h2>
<div style="background:#1a1a2e;border-radius:12px;padding:20px;margin:16px 0;text-align:left">
<label style="font-size:12px;color:#888">ID:</label><div class=cv>{{uid}}</div>
<button class=cp onclick="navigator.clipboard.writeText('{{uid}}');this.textContent='✅'">📋</button><br>
<label style="font-size:12px;color:#888">Пароль:</label><div class=cv>{{pw}}</div>
<button class=cp onclick="navigator.clipboard.writeText('{{pw}}');this.textContent='✅'">📋</button></div>
<div class=warn>⚠️ Сохраните! Пароль больше не покажется</div>
<a href=/login class=btn style="display:inline-block;width:auto;padding:12px 30px">Войти →</a></div>
{%else%}<form method=POST>{%if e%}<div class=err>❌ {{e}}</div>{%endif%}
<div class=fg><label>Имя</label><input name=n required></div>
<div class=fg><label>Email</label><input type=email name=m required></div>
<div class=fg><label>Пароль (опционально)</label><input type=password name=p placeholder="Мин 8 символов"></div>
<button class=btn>🔐 Создать</button></form><div class=ft>Есть аккаунт? <a href=/login>Войти</a></div>{%endif%}
</div></div></body></html>"""

PV="""<!DOCTYPE html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>2FA</title><style>"""+CSS+"""</style></head><body><div class=ac><div class=cd>
<div style="text-align:center;font-size:48px;margin-bottom:10px">🔑</div>
<h1>Проверка</h1><p class=sub>Код отправлен на {{h}}</p>
<form method=POST action=/v2>{%if e%}<div class=err>❌ {{e}}</div>{%endif%}
<div class=fg><label>Код</label><input name=c class=ci6 maxlength=6 required inputmode=numeric autofocus></div>
<button class=btn>✅ Подтвердить</button></form>
<div class=ft><a href=/login>← Назад</a></div></div></div>
<script>document.querySelector('.ci6').addEventListener('input',function(){
this.value=this.value.replace(/\\D/g,'');if(this.value.length===6)this.closest('form').submit()})</script></body></html>"""

PC="""<!DOCTYPE html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>SecureMessenger</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.4/socket.io.min.js"></script>
<style>"""+CSS+"""</style></head><body>
<div class=ms>
<aside class=sb id=sb><div class=sh><div style="display:flex;align-items:center;gap:10px">
<div class=av>{{u.name[0]|upper}}</div><div><span style="font-weight:600;font-size:14px">{{u.name}}</span><br>
<span style="font-size:11px;color:#555;font-family:monospace">{{u.id}}</span></div></div>
<div><button class=ib onclick="openModal('acm')">➕</button>
<button class=ib onclick="location.href='/out'">🚪</button></div></div>
<div class=ss><input id=sf placeholder="🔍 Поиск"></div>
<div class=cl id=cl>{%for c in cts%}<div class=ci data-id="{{c.id}}" onclick="oc('{{c.id}}','{{c.name}}')">
<div class="av {{'on'if c.status=='online'}}">{{c.name[0]|upper}}</div>
<div style="flex:1;min-width:0"><span class=cn>{{c.name}}</span>
<span class=cs>{{'🟢'if c.status=='online'else'⚫'}}</span></div>
{%if ur.get(c.id,0)>0%}<div class=ub>{{ur[c.id]}}</div>{%endif%}</div>{%endfor%}</div></aside>
<main class=ma><div class=ec id=ec><div class=ei>💬</div><h2>SecureMessenger</h2>
<p style="margin-top:16px;font-size:14px">ID: <strong style="color:#0df;font-family:monospace">{{u.id}}</strong>
<button class=cp onclick="navigator.clipboard.writeText('{{u.id}}')">📋</button></p></div>
<div id=ac style="display:none;flex-direction:column;height:100%">
<div class=mh><div style="display:flex;align-items:center;gap:12px">
<div class=av id=cav></div><div><span id=cun style="font-weight:600"></span><br>
<span id=cus class=cs></span></div></div>
<div><button class=ib onclick="sc('audio')">📞</button>
<button class=ib onclick="sc('video')">📹</button></div></div>
<div class=mc id=mc><div class=ml id=ml></div>
<div class=tp id=tp style=display:none>печатает...</div></div>
<div class=mi><div class=iw><textarea id=inp placeholder="Сообщение..." rows=1></textarea>
<button class=snb onclick=sm()><svg viewBox="0 0 24 24" width=22 height=22>
<path fill=currentColor d="M2,21L23,12L2,3V10L17,12L2,14V21Z"/></svg></button></div></div></div></main></div>
<!-- Модалка -->
<div class=mo id=acm style=display:none onclick="if(event.target===this)closeModal('acm')">
<div class=md><h3 style=margin-bottom:16px>Добавить контакт</h3>
<div class=fg><input id=nci placeholder="SM-XXXXXXXX" style="text-transform:uppercase"></div>
<div id=acr></div><div style="display:flex;gap:10px;margin-top:16px">
<button class=btn style="background:#1a1a2e;color:#e0e0e0" onclick="closeModal('acm')">Отмена</button>
<button class=btn onclick=addC()>Добавить</button></div></div></div>
<!-- Входящий -->
<div class=co id=ico style=display:none><div class=cc>
<div style="position:relative;width:120px;height:120px;margin:0 auto 30px">
<div class=rp></div><div class=rp style="animation-delay:.5s"></div>
<div class=av style="width:100px;height:100px;font-size:40px;position:absolute;top:10px;left:10px;z-index:3" id=icav></div></div>
<h2 id=icn></h2><p style="color:#888;margin-bottom:30px" id=ict></p>
<div style="display:flex;justify-content:center;gap:60px">
<button class=cab onclick=dcl()><span style="background:#e94560">📵</span><label style="color:#888">Отклонить</label></button>
<button class=cab onclick=acl()><span style="background:#0e6">📞</span><label style="color:#888">Принять</label></button></div></div></div>
<!-- Активный звонок -->
<div class=co id=aco style=display:none><div style="width:100%;height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center">
<div style=text-align:center;margin-bottom:30px><h2 id=acn></h2><p id=acs style="color:#888">Вызов...</p>
<p class=ct id=act>00:00</p></div>
<div class=vc id=vc style=display:none><video id=rv autoplay playsinline></video>
<video id=lv autoplay playsinline muted class=lv></video></div>
<div class=ccs><button class=ccb id=tmb onclick=tgm()><span>🎤</span></button>
<button class=ccb id=tcb onclick=tgc() style=display:none><span>📷</span></button>
<button class="ccb ec" onclick=ecl()><span>📵</span></button></div></div></div>
<script>
const U={id:'{{u.id}}',n:'{{u.name}}',s:'{{sid}}'};
const ICE={{ice|safe}};
let sk,cc=null,pc=null,ls=null,ci=null,ct=null,cp=null,cti=null,cst=null,rctx=null,rto=null;
sk=io({transports:['websocket','polling'],reconnection:true});
sk.on('connect',()=>sk.emit('authenticate',{session_id:U.s}));
sk.on('authenticated',()=>nt('Подключено','s'));
sk.on('auth_error',()=>{location.href='/login'});
sk.on('new_message',onM);sk.on('user_typing',d=>{if(d.user_id===cc)$('tp').style.display='flex'});
sk.on('user_stop_typing',d=>{if(d.user_id===cc)$('tp').style.display='none'});
sk.on('user_online',d=>{let e=document.querySelector('[data-id="'+d.user_id+'"] .av');
if(e)e.classList.add('on');if(d.user_id===cc)$('cus').textContent='🟢'});
sk.on('user_offline',d=>{let e=document.querySelector('[data-id="'+d.user_id+'"] .av');
if(e)e.classList.remove('on');if(d.user_id===cc)$('cus').textContent='⚫'});
sk.on('incoming_call',onIC);sk.on('call_ringing',d=>{ci=d.call_id;shC(cp,ct,'Вызов...');stR()});
sk.on('call_accepted',onAC);
sk.on('call_declined',()=>{spR();hC();clC();nt('Отклонён','w')});
sk.on('call_ended',d=>{spR();hC();clC();nt('Завершён')});
sk.on('call_error',d=>{spR();hC();clC();nt(d.error||'Ошибка','e')});
sk.on('webrtc_offer',onOF);sk.on('webrtc_answer',onAN);sk.on('webrtc_ice_candidate',onICC);
function $(i){return document.getElementById(i)}
function esc(t){let d=document.createElement('div');d.textContent=t;return d.innerHTML}
function ft(ts){return new Date(ts*1000).toLocaleTimeString('ru',{hour:'2-digit',minute:'2-digit'})}
function fd(s){return String(Math.floor(s/60)).padStart(2,'0')+':'+String(s%60).padStart(2,'0')}
function nt(m,t='i'){let d=document.createElement('div');d.className='nt';
d.style.borderLeft='3px solid '+(t==='s'?'#0e6':t==='e'?'#e94560':'#0df');
d.textContent=m;document.body.appendChild(d);setTimeout(()=>d.remove(),3000)}
function openModal(i){$(i).style.display='flex'}
function closeModal(i){$(i).style.display='none'}
// Chat
function oc(id,nm){cc=id;$('ec').style.display='none';$('ac').style.display='flex';
$('cun').textContent=nm;$('cav').textContent=nm[0].toUpperCase();
document.querySelectorAll('.ci').forEach(e=>e.classList.toggle('at',e.dataset.id===id));
let b=document.querySelector('[data-id="'+id+'"] .ub');if(b)b.remove();
lm(id);sk.emit('mark_read',{sender_id:id});$('inp').focus()}
async function lm(cid){$('ml').innerHTML='...';
try{let r=await fetch('/api/m/'+cid,{headers:{'X-S':U.s}});let d=await r.json();
$('ml').innerHTML='';if(d.m&&d.m.length)d.m.forEach(am);else $('ml').innerHTML='<div style="text-align:center;color:#555;padding:40px">💬 Начните</div>';sb()}catch(e){}}
function sm(){let inp=$('inp'),c=inp.value.trim();if(!c||!cc)return;
sk.emit('send_message',{receiver_id:cc,content:c});
am({sender:U.id,content:c,ts:Date.now()/1000});inp.value='';inp.style.height='auto';sb()}
function am(m){let d=document.createElement('div');d.className='mg '+(m.sender===U.id?'s':'r');
d.innerHTML='<div>'+esc(m.content)+'</div><div class=mt>'+ft(m.ts)+'</div>';$('ml').appendChild(d)}
function sb(){let c=$('mc');if(c)setTimeout(()=>c.scrollTop=c.scrollHeight,50)}
function onM(m){if(m.sender_id!==cc){nt('💬 '+m.sender_id);
let b=document.querySelector('[data-id="'+m.sender_id+'"] .ub');
if(!b){b=document.createElement('div');b.className='ub';b.textContent='1';
let ci=document.querySelector('[data-id="'+m.sender_id+'"]');if(ci)ci.appendChild(b)}
else b.textContent=parseInt(b.textContent)+1}
if(m.sender_id===cc){am(m);sb();sk.emit('mark_read',{sender_id:m.sender_id})}}
$('inp').addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();sm()}});
$('inp').addEventListener('input',function(){this.style.height='auto';this.style.height=Math.min(this.scrollHeight,120)+'px';
if(cc){sk.emit('typing',{receiver_id:cc});clearTimeout(window._tt);
window._tt=setTimeout(()=>sk.emit('stop_typing',{receiver_id:cc}),2000)}});
$('sf').addEventListener('input',function(){let q=this.value.toLowerCase();
document.querySelectorAll('.ci').forEach(e=>{e.style.display=e.querySelector('.cn').textContent.toLowerCase().includes(q)?'':'none'})});
async function addC(){let id=$('nci').value.trim().toUpperCase(),r=$('acr');
if(!id){r.innerHTML='<p style="color:#e94560">Введите ID</p>';return}
try{let res=await fetch('/api/c/add',{method:'POST',headers:{'Content-Type':'application/json','X-S':U.s},
body:JSON.stringify({c:id})});let d=await res.json();
if(d.ok){let c=d.ct,div=document.createElement('div');div.className='ci';div.dataset.id=c.id;
div.onclick=()=>oc(c.id,c.name);
div.innerHTML='<div class=av>'+c.name[0].toUpperCase()+'</div><div style="flex:1"><span class=cn>'+esc(c.name)+'</span><span class=cs>⚫</span></div>';
$('cl').appendChild(div);closeModal('acm');$('nci').value='';r.innerHTML='';nt('Добавлен!','s')}
else r.innerHTML='<p style="color:#e94560">'+d.e+'</p>'}catch(e){}}
// Calls + WebRTC
function stR(){try{rctx=new(window.AudioContext||window.webkitAudioContext)();_rp()}catch(e){}}
function _rp(){if(!rctx)return;let t=rctx.currentTime;
[880,1100,880,1100].forEach((f,i)=>{let o=rctx.createOscillator(),g=rctx.createGain();
o.connect(g);g.connect(rctx.destination);o.frequency.value=f;o.type='sine';
let s=t+i*.18;g.gain.setValueAtTime(.3,s);g.gain.exponentialRampToValueAtTime(.01,s+.15);
o.start(s);o.stop(s+.15)});rto=setTimeout(_rp,1500)}
function spR(){if(rctx){rctx.close().catch(()=>{});rctx=null}clearTimeout(rto)}
function sc(type){if(!cc)return;ct=type;cp=cc;sk.emit('call_initiate',{receiver_id:cc,call_type:type})}
function onIC(d){ci=d.call_id;ct=d.call_type;cp=d.caller_id;
$('ico').style.display='flex';$('icav').textContent=d.caller_name[0].toUpperCase();
$('icn').textContent=d.caller_name;$('ict').textContent=d.call_type==='video'?'📹':'📞';stR()}
function acl(){$('ico').style.display='none';spR();sk.emit('call_accept',{call_id:ci});
shC(cp,ct,'Подключение...');sM(ct).catch(()=>{ecl();nt('Нет доступа','e')})}
function dcl(){$('ico').style.display='none';spR();sk.emit('call_decline',{call_id:ci,caller_id:cp});ci=null;cp=null}
async function onAC(){spR();$('acs').textContent='Подключение...';
try{await sM(ct);await cPC();let o=await pc.createOffer({offerToReceiveAudio:true,offerToReceiveVideo:ct==='video'});
await pc.setLocalDescription(o);sk.emit('webrtc_offer',{call_id:ci,sdp:o,target_id:cp})}catch(e){ecl()}}
async function sM(type){let c={audio:{echoCancellation:true,noiseSuppression:true},
video:type==='video'?{width:{ideal:1280},height:{ideal:720}}:false};
ls=await navigator.mediaDevices.getUserMedia(c);
if(type==='video'){$('lv').srcObject=ls;$('vc').style.display='block';$('tcb').style.display='flex'}}
async function cPC(){pc=new RTCPeerConnection({iceServers:ICE});
if(ls)ls.getTracks().forEach(t=>pc.addTrack(t,ls));
pc.ontrack=e=>{$('rv').srcObject=e.streams[0];$('acs').textContent='';
cst=Date.now();cti=setInterval(()=>$('act').textContent=fd(Math.floor((Date.now()-cst)/1000)),1000)};
pc.onicecandidate=e=>{if(e.candidate)sk.emit('webrtc_ice_candidate',{call_id:ci,candidate:e.candidate.toJSON(),target_id:cp})};
pc.oniceconnectionstatechange=()=>{if(pc.iceConnectionState==='failed')ecl()}}
async function onOF(d){try{await cPC();await pc.setRemoteDescription(new RTCSessionDescription(d.sdp));
let a=await pc.createAnswer();await pc.setLocalDescription(a);
sk.emit('webrtc_answer',{call_id:d.call_id,sdp:a,target_id:d.from_id})}catch(e){ecl()}}
async function onAN(d){try{await pc.setRemoteDescription(new RTCSessionDescription(d.sdp))}catch(e){}}
async function onICC(d){try{if(pc&&d.candidate)await pc.addIceCandidate(new RTCIceCandidate(d.candidate))}catch(e){}}
function tgm(){if(!ls)return;let t=ls.getAudioTracks()[0];if(t){t.enabled=!t.enabled;
$('tmb').classList.toggle('mu',!t.enabled);$('tmb').querySelector('span').textContent=t.enabled?'🎤':'🔇'}}
function tgc(){if(!ls)return;let t=ls.getVideoTracks()[0];if(t){t.enabled=!t.enabled;
$('tcb').classList.toggle('mu',!t.enabled)}}
function ecl(){spR();if(ci)sk.emit('call_end',{call_id:ci});hC();clC()}
function clC(){if(pc){pc.close();pc=null}if(ls){ls.getTracks().forEach(t=>t.stop());ls=null}
if(cti)clearInterval(cti);ci=null;cp=null;ct=null;cst=null}
function shC(p,t,s){$('aco').style.display='flex';$('acn').textContent=p;$('acs').textContent=s;
$('act').textContent='00:00';if(t==='video')$('tcb').style.display='flex'}
function hC(){$('aco').style.display='none';$('ico').style.display='none';
$('vc').style.display='none';$('tcb').style.display='none'}
if('Notification'in window&&Notification.permission==='default')Notification.requestPermission();
</script></body></html>"""

# ─── Routes ───
@app.route('/')
def idx():
    if session.get('sid')and chks(session['sid']):return redirect('/chat')
    return redirect('/login')

@app.route('/r',methods=['GET','POST'])
def rp():
    if request.method=='GET':return render_template_string(PR,ok=False,e=None)
    m=request.form.get('m','').strip();n=request.form.get('n','').strip();p=request.form.get('p','').strip()
    if not m or not n:return render_template_string(PR,ok=False,e='Заполните поля')
    r=reg(m,n,p if p else None)
    if r['ok']:return render_template_string(PR,ok=True,uid=r['uid'],pw=r['pw'])
    return render_template_string(PR,ok=False,e=r['err'])

@app.route('/login',methods=['GET','POST'])
def lp():
    if request.method=='GET':return render_template_string(PL,e=None)
    u=request.form.get('u','').strip().upper();p=request.form.get('p','').strip()
    if not u or not p:return render_template_string(PL,e='Заполните поля')
    r=login1(u,p,request.headers.get('User-Agent',''),request.remote_addr)
    if not r['ok']:return render_template_string(PL,e=r['err'])
    if r.get('2fa'):
        session['2u']=u;session['2d']=request.headers.get('User-Agent','');session['2i']=request.remote_addr
        return render_template_string(PV,h=r.get('hint',''),e=None)
    session['sid']=r['sid'];session['uid']=r['uid'];return redirect('/chat')

@app.route('/v2',methods=['POST'])
def v2():
    u=session.get('2u')
    if not u:return redirect('/login')
    c=request.form.get('c','').strip()
    r=login2(u,c,session.get('2d',''),session.get('2i',''))
    if r['ok']:session.pop('2u',None);session['sid']=r['sid'];session['uid']=r['uid'];return redirect('/chat')
    return render_template_string(PV,h='',e=r['err'])

@app.route('/chat')
@lreq
def cp_page(uid):
    u=db.get_user(uid);cts=db.get_cts(uid);ur=db.unread(uid)
    return render_template_string(PC,u=u,cts=cts,ur=ur,sid=session['sid'],ice=json.dumps(ICE))

@app.route('/out')
def out():
    sid=session.get('sid')
    if sid:s=db.get_sess(sid);db.set_st(s['uid'],'offline')if s else 0;db.del_sess(sid)
    session.clear();return redirect('/login')

@app.route('/api/c/add',methods=['POST'])
@aauth
def aac(uid):
    d=request.get_json();cid=d.get('c','').strip().upper()
    if not cid:return jsonify({'e':'Введите ID'}),400
    if cid==uid:return jsonify({'e':'Нельзя себя'}),400
    if not db.exists(cid):return jsonify({'e':'Не найден'}),404
    db.add_ct(uid,cid);c=db.get_user(cid)
    return jsonify({'ok':1,'ct':{'id':c['id'],'name':c['name'],'status':c['status']}})

@app.route('/api/m/<cid>')
@aauth
def agm(uid,cid):
    ms=db.get_msgs(uid,cid);db.mark_rd(uid,cid);return jsonify({'m':ms})

# ─── WebSocket ───
@sio.on('connect')
def wc():pass

@sio.on('authenticate')
def wa(d):
    sid=d.get('session_id')
    if not sid:disconnect();return
    uid=chks(sid)
    if not uid:emit('auth_error',{});disconnect();return
    s=request.sid;SM[s]=uid;ON.setdefault(uid,set()).add(s);join_room(uid)
    db.set_st(uid,'online')
    for c in db.get_cts(uid):
        if c['id']in ON:
            for cs in ON[c['id']]:emit('user_online',{'user_id':uid},room=cs)
    emit('authenticated',{'user_id':uid})

@sio.on('disconnect')
def wd():
    s=request.sid;uid=SM.pop(s,None)
    if uid and uid in ON:
        ON[uid].discard(s)
        if not ON[uid]:
            del ON[uid];db.set_st(uid,'offline')
            for c in db.get_cts(uid):
                if c['id']in ON:
                    for cs in ON[c['id']]:emit('user_offline',{'user_id':uid},room=cs)
        leave_room(uid)

@sio.on('send_message')
def wm(d):
    uid=SM.get(request.sid)
    if not uid:return
    ri=d.get('receiver_id','').strip();ct=d.get('content','').strip()
    if not ri or not ct or len(ct)>10000:return
    mid=db.save_msg(uid,ri,ct)
    md={'id':mid,'sender_id':uid,'receiver_id':ri,'content':ct,'timestamp':time.time()}
    if ri in ON:
        for rs in ON[ri]:emit('new_message',md,room=rs)
    emit('message_sent',md)

@sio.on('typing')
def wt(d):
    uid=SM.get(request.sid);ri=d.get('receiver_id')
    if uid and ri and ri in ON:
        for rs in ON[ri]:emit('user_typing',{'user_id':uid},room=rs)

@sio.on('stop_typing')
def wst(d):
    uid=SM.get(request.sid);ri=d.get('receiver_id')
    if uid and ri and ri in ON:
        for rs in ON[ri]:emit('user_stop_typing',{'user_id':uid},room=rs)

@sio.on('mark_read')
def wmr(d):
    uid=SM.get(request.sid);si=d.get('sender_id')
    if uid and si:db.mark_rd(uid,si)

# ─── Calls ───
@sio.on('call_initiate')
def wci(d):
    uid=SM.get(request.sid)
    if not uid:return
    ri=d.get('receiver_id');ctp=d.get('call_type','audio')
    if not ri or ri not in ON:emit('call_error',{'error':'Офлайн'});return
    for c in AC.values():
        if uid in(c['ca'],c['re']):emit('call_error',{'error':'Вы в звонке'});return
        if ri in(c['ca'],c['re']):emit('call_error',{'error':'Занят'});return
    cid=gcid();AC[cid]={'ca':uid,'re':ri,'tp':ctp,'st':'ring','ts':time.time()}
    db.save_call(cid,uid,ri,ctp);u=db.get_user(uid)
    for rs in ON.get(ri,set()):
        emit('incoming_call',{'call_id':cid,'caller_id':uid,'caller_name':u['name'],'call_type':ctp},room=rs)
    emit('call_ringing',{'call_id':cid,'receiver_id':ri})

@sio.on('call_accept')
def wca(d):
    uid=SM.get(request.sid);cid=d.get('call_id');c=AC.get(cid)
    if not c or c['re']!=uid:return
    c['st']='acc'
    for cs in ON.get(c['ca'],set()):emit('call_accepted',{'call_id':cid},room=cs)

@sio.on('call_decline')
def wcd(d):
    uid=SM.get(request.sid);cid=d.get('call_id');c=AC.pop(cid,None)
    if not c:return
    db.end_call(cid,'dec');ot=c['ca']if c['re']==uid else c['re']
    for s in ON.get(ot,set()):emit('call_declined',{'call_id':cid},room=s)

@sio.on('call_end')
def wce(d):
    uid=SM.get(request.sid);cid=d.get('call_id');c=AC.pop(cid,None)
    if not c:return
    dur=int(time.time()-c['ts'])if c['st']=='acc'else 0;db.end_call(cid,'end',dur)
    ot=c['ca']if c['re']==uid else c['re']
    for s in ON.get(ot,set()):emit('call_ended',{'call_id':cid,'duration':dur},room=s)

@sio.on('webrtc_offer')
def wo(d):
    uid=SM.get(request.sid);ti=d.get('target_id')
    if ti and ti in ON:
        for s in ON[ti]:emit('webrtc_offer',{'call_id':d.get('call_id'),'sdp':d.get('sdp'),'from_id':uid},room=s)

@sio.on('webrtc_answer')
def wan(d):
    uid=SM.get(request.sid);ti=d.get('target_id')
    if ti and ti in ON:
        for s in ON[ti]:emit('webrtc_answer',{'call_id':d.get('call_id'),'sdp':d.get('sdp'),'from_id':uid},room=s)

@sio.on('webrtc_ice_candidate')
def wic(d):
    uid=SM.get(request.sid);ti=d.get('target_id')
    if ti and ti in ON:
        for s in ON[ti]:emit('webrtc_ice_candidate',{'call_id':d.get('call_id'),'candidate':d.get('candidate'),'from_id':uid},room=s)

# Таймаут звонков
def _ct():
    while True:
        time.sleep(5);now=time.time()
        for k in[k for k,v in AC.items()if v['st']=='ring'and now-v['ts']>45]:
            c=AC.pop(k,None)
            if c:
                db.end_call(k,'miss')
                for uid in(c['ca'],c['re']):
                    if uid in ON:
                        for s in ON[uid]:sio.emit('call_ended',{'call_id':k,'duration':0},room=s)
threading.Thread(target=_ct,daemon=True).start()

# ─── Start ───
if __name__=='__main__':
    print(f"\n🔐 SecureMessenger | http://{HOST}:{PORT}\n")
    sio.run(app,host=HOST,port=PORT,debug=False,allow_unsafe_werkzeug=True)
