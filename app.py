import os, sqlite3, secrets, subprocess, re, json, urllib.request, urllib.parse, sys, hashlib, base64, grp, time, ssl, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from flask import Flask, request, session, redirect, abort, make_response, Response, send_from_directory
from werkzeug.serving import ThreadedWSGIServer

APP_DIR=os.environ.get('HY_CONTROL_DIR','/opt/hysteria-control')
DB=os.environ.get('PANEL_DB',os.path.join(APP_DIR,'panel.db'))
DOMAIN=os.environ['PANEL_DOMAIN']
API=os.environ.get('HYSTERIA_API','http://127.0.0.1:9999')
API_SECRET_FILE=os.environ.get('HYSTERIA_API_SECRET_FILE','/etc/hysteria/api-secret')
HY2_CONFIG=os.environ.get('HYSTERIA_CONFIG','/etc/hysteria/config.yaml')
PANEL_CERT=os.environ.get('PANEL_CERT','/etc/letsencrypt/live/'+DOMAIN+'/fullchain.pem')
PANEL_KEY=os.environ.get('PANEL_KEY','/etc/letsencrypt/live/'+DOMAIN+'/privkey.pem')
PANEL_PORT=int(os.environ.get('PANEL_PORT','8443'))
AUTH_PORT=int(os.environ.get('HYSTERIA_AUTH_PORT','9998'))
DYNAMIC_AUTH=os.environ.get('HYSTERIA_DYNAMIC_AUTH')=='1'
app=Flask(__name__); app.secret_key=os.environ['PANEL_SECRET']
app.config.update(SESSION_COOKIE_SECURE=True,SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Lax')
last_cpu=None; last_net=None; last_sample=0
db_ready=False
db_init_lock=threading.Lock()
add_states={}
delete_states={}
add_states_lock=threading.Lock()

def conn():
    global db_ready
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row
    if not db_ready:
        with db_init_lock:
            if not db_ready:
                c.execute('create table if not exists users(username text primary key,password text not null,enabled integer not null default 1)')
                c.execute('create table if not exists usage(username text primary key,tx integer not null default 0,rx integer not null default 0,last_tx integer not null default 0,last_rx integer not null default 0)')
                c.execute('create table if not exists settings(key text primary key,value text not null)')
                c.commit(); db_ready=True
    return c
def setting(key,default=''):
    c=conn(); r=c.execute('select value from settings where key=?',(key,)).fetchone(); c.close(); return r['value'] if r else default
def put_setting(key,value):
    c=conn(); c.execute('insert into settings values(?,?) on conflict(key) do update set value=excluded.value',(key,value)); c.commit(); c.close()
def hash_password(password):
    salt=secrets.token_bytes(16); rounds=310000
    digest=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,rounds)
    return f'pbkdf2_sha256${rounds}${base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(digest).decode()}'
def verify_password(password,encoded):
    try:
        scheme,rounds,salt,digest=encoded.split('$',3)
        rounds=int(rounds)
        if scheme!='pbkdf2_sha256' or not 100000<=rounds<=1000000: return False
        candidate=hashlib.pbkdf2_hmac('sha256',password.encode(),base64.urlsafe_b64decode(salt),rounds)
        return secrets.compare_digest(base64.urlsafe_b64encode(candidate).decode(),digest)
    except (ValueError,TypeError): return False
def admin_password_matches(password):
    stored=setting('admin_password_hash')
    if stored: return verify_password(password,stored)
    return secrets.compare_digest(password,os.environ['PANEL_PASS'])
def auth_version(): return setting('admin_auth_version','legacy')
def api_get(path):
    with open(API_SECRET_FILE) as f: secret=f.read().strip()
    req=urllib.request.Request(API+path,headers={'Authorization':secret})
    with urllib.request.urlopen(req,timeout=1) as r: return json.loads(r.read())

def kick_user(username):
    try:
        with open(API_SECRET_FILE) as f: secret=f.read().strip()
        req=urllib.request.Request(API+'/kick',data=json.dumps([username]).encode(),headers={'Authorization':secret,'Content-Type':'application/json'},method='POST')
        with urllib.request.urlopen(req,timeout=1): pass
    except Exception:
        app.logger.exception('Could not disconnect disabled or deleted Hysteria user')
def record_traffic():
    try: traffic=api_get('/traffic')
    except Exception: return
    c=conn()
    changed=False
    for name,v in traffic.items():
        owner=c.execute('select username from users where username=? collate nocase',(name,)).fetchone()
        if not owner: continue
        name=owner['username']
        tx=max(0,int(v.get('tx',0))); rx=max(0,int(v.get('rx',0)))
        old=c.execute('select tx,rx,last_tx,last_rx from usage where username=?',(name,)).fetchone()
        if old:
            if tx==old['last_tx'] and rx==old['last_rx']: continue
            addtx=tx-old['last_tx'] if tx>=old['last_tx'] else tx
            addrx=rx-old['last_rx'] if rx>=old['last_rx'] else rx
            c.execute('update usage set tx=tx+?,rx=rx+?,last_tx=?,last_rx=? where username=?',(max(0,addtx),max(0,addrx),tx,rx,name))
        else: c.execute('insert into usage(username,tx,rx,last_tx,last_rx) values(?,?,?,?,?)',(name,tx,rx,tx,rx))
        changed=True
    if changed: c.commit()
    c.close()
def write_server_config():
    record_traffic()
    c=conn(); rows=c.execute('select username,password from users where enabled=1 order by username').fetchall(); c.close()
    if not rows: raise ValueError('At least one Hysteria user must remain enabled')
    with open(API_SECRET_FILE) as f: api_secret=f.read().strip()
    lines=['listen: :443','tls:','  cert: '+PANEL_CERT,'  key: '+PANEL_KEY,'auth:']
    if DYNAMIC_AUTH:
        lines += ['  type: http','  http:','    url: http://127.0.0.1:'+str(AUTH_PORT)+'/auth']
    else:
        lines += ['  type: userpass','  userpass:']
        lines += [f'    {r["username"]}: {r["password"]}' for r in rows]
    lines += ['trafficStats:','  listen: 127.0.0.1:9999','  secret: '+api_secret,'masquerade:','  type: proxy','  proxy:','    url: https://www.bing.com/','    rewriteHost: true']
    os.makedirs(os.path.dirname(HY2_CONFIG),exist_ok=True)
    p=HY2_CONFIG; tmp=p+'.tmp'
    with open(tmp,'w') as f: f.write('\n'.join(lines)+'\n')
    os.chown(tmp,0,grp.getgrnam('hysteria-control').gr_gid)
    os.chmod(tmp,0o640); os.replace(tmp,p)
    subprocess.run(['systemctl','restart','hysteria-server'],check=True)

def sync():
    if DYNAMIC_AUTH: return
    subprocess.run(['/usr/bin/sudo','-n','/usr/local/sbin/hysteria-control-sync'],check=True)

class HysteriaAuthHandler(BaseHTTPRequestHandler):
    def setup(self):
        self.request.settimeout(3)
        super().setup()

    def do_POST(self):
        if self.path!='/auth':
            self.send_error(404); return
        try:
            size=int(self.headers.get('Content-Length','0'))
            if not 0<size<=2048: raise ValueError('invalid body size')
            payload=json.loads(self.rfile.read(size))
            auth=payload.get('auth','')
            if not isinstance(auth,str) or len(auth)>512: raise ValueError('invalid auth')
            username,separator,password=auth.partition(':')
            if not separator or not re.fullmatch(r'[A-Za-z0-9_-]{1,32}',username): raise ValueError('invalid user')
            c=conn()
            try: user=c.execute('select username,password,enabled from users where username=?',(username,)).fetchone()
            finally: c.close()
            allowed=bool(user and user['enabled'] and secrets.compare_digest(password,user['password']))
            body=json.dumps({'ok':allowed,'id':user['username'] if allowed else ''}).encode()
        except (ValueError,TypeError,json.JSONDecodeError,sqlite3.Error):
            body=b'{"ok":false,"id":""}'
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self,*args):
        pass

def page(body):
    theme=request.cookies.get('theme','system')
    if theme not in ('system','light','dark'): theme='system'
    lang='en' if request.cookies.get('language')=='en' else 'ru'
    css='''
@font-face{font-family:IBM Plex Sans;src:url('/fonts/ibm-plex-sans-latin.woff2') format('woff2');font-weight:400 700;unicode-range:U+0000-00FF}@font-face{font-family:IBM Plex Sans;src:url('/fonts/ibm-plex-sans-cyrillic.woff2') format('woff2');font-weight:400 700;unicode-range:U+0301,U+0400-045F,U+0490-0491,U+04B0-04B1,U+2116}@font-face{font-family:IBM Plex Mono;src:url('/fonts/ibm-plex-mono-latin.woff2') format('woff2');font-weight:400 600;unicode-range:U+0000-00FF}@font-face{font-family:IBM Plex Mono;src:url('/fonts/ibm-plex-mono-cyrillic.woff2') format('woff2');font-weight:400 600;unicode-range:U+0301,U+0400-045F,U+0490-0491,U+04B0-04B1,U+2116}
@font-face{font-family:IBM Plex Sans;src:url('/fonts/ibm-plex-sans-latin.woff2') format('woff2');font-weight:400 700;unicode-range:U+0000-00FF}@font-face{font-family:IBM Plex Sans;src:url('/fonts/ibm-plex-sans-cyrillic.woff2') format('woff2');font-weight:400 700;unicode-range:U+0301,U+0400-045F,U+0490-0491,U+04B0-04B1,U+2116}@font-face{font-family:IBM Plex Mono;src:url('/fonts/ibm-plex-mono-latin.woff2') format('woff2');font-weight:400 600;unicode-range:U+0000-00FF}@font-face{font-family:IBM Plex Mono;src:url('/fonts/ibm-plex-mono-cyrillic.woff2') format('woff2');font-weight:400 600;unicode-range:U+0301,U+0400-045F,U+0490-0491,U+04B0-04B1,U+2116}
*{box-sizing:border-box}body{margin:0;font:15px/1.55 'IBM Plex Sans',sans-serif;background:var(--bg);color:var(--text);transition:background .2s,color .2s}:root{color-scheme:dark;--bg:#000;--panel:#0b0b0b;--card:#101010;--card2:#171717;--text:#f5f4f1;--muted:#aaa7a2;--border:#292724;--accent:#ff5733;--accent2:#f04b28;--accent-soft:#2a130e;--good:#42cf9b;--bad:#ff6e6e;--input:#090909;--shadow:0 12px 32px #0008}body.light{color-scheme:light;--bg:#f2f0eb;--panel:#fff;--card:#fff;--card2:#f8f8f5;--text:#152536;--muted:#64758a;--border:#dce5eb;--accent:#55bdec;--accent2:#269edb;--accent-soft:#e4f5fc;--good:#16a976;--bad:#d74d52;--input:#fff;--shadow:0 10px 28px #2e52640c}
a{color:inherit;text-decoration:none}button,input,select{font:inherit}button{border:1px solid var(--border);border-radius:12px;padding:9px 13px;background:var(--card2);color:var(--text);cursor:pointer;transition:.15s}button:hover{border-color:var(--accent);transform:translateY(-1px)}button.primary{background:var(--accent2);border-color:var(--accent2);color:#fff}button.danger{color:var(--bad)}input,select{border:1px solid var(--border);border-radius:12px;padding:10px 12px;background:var(--input);color:var(--text);outline:none}input:focus,select:focus{border-color:var(--accent)}.shell{max-width:1340px;margin:auto;padding:38px 32px 64px}.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:36px}.brand{display:flex;gap:16px;align-items:center}.logo{width:56px;height:56px;border-radius:16px;background:var(--accent);display:grid;place-items:center;color:white;font-weight:600;font-size:25px}.brand h1{font-size:24px;margin:0;letter-spacing:-.5px}.brand small{display:block;color:var(--muted);font-size:14px}.top-actions{display:flex;align-items:center;gap:10px}.gear-menu{position:relative}.gear-popover{position:absolute;right:0;top:calc(100% + 12px);z-index:30;width:min(370px,calc(100vw - 30px));padding:18px}.gear-popover[hidden]{display:none}.gear-popover h3{font-size:16px;margin:0 0 13px}.setting-line{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:10px 0;border-top:1px solid var(--border)}.setting-line select{min-width:125px}.password-popover{margin-top:10px;padding-top:13px;border-top:1px solid var(--border)}.password-popover[hidden]{display:none}.password-popover form{display:grid;gap:8px}.password-popover h4{margin:0 0 8px}.theme{width:42px;height:42px;display:grid;place-items:center}.icon-button{font-size:20px}.hero{display:flex;justify-content:space-between;align-items:end;margin:12px 0 21px}.hero h2{font-size:30px;letter-spacing:-1px;margin:0}.hero p{margin:5px 0 0;color:var(--muted)}.live{display:flex;align-items:center;gap:8px;color:var(--muted);font-size:13px}.lamp{width:10px;height:10px;border-radius:50%;background:var(--good);box-shadow:0 0 0 4px color-mix(in srgb,var(--good) 16%,transparent),0 0 13px color-mix(in srgb,var(--good) 65%,transparent);display:inline-block}.lamp.off{background:var(--bad);box-shadow:0 0 0 4px color-mix(in srgb,var(--bad) 16%,transparent),0 0 13px color-mix(in srgb,var(--bad) 55%,transparent)}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}.card{background:var(--card);border:1px solid var(--border);border-radius:20px;padding:20px;box-shadow:var(--shadow)}.metric .label{color:var(--muted);font-size:13px}.metric strong{display:block;font-size:27px;letter-spacing:-.7px;margin-top:7px;font-weight:600}.metric .sub{font-size:12px;color:var(--muted);margin-top:4px}.section-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin:32px 0 14px}.section-head h3{font-size:21px;margin:0;letter-spacing:-.3px}.section-head p{font-size:13px;color:var(--muted);margin:4px 0 0}.server-card{margin-top:16px}.bar{height:5px;background:var(--border);border-radius:5px;margin-top:13px;overflow:hidden}.bar i{height:100%;display:block;width:0;background:var(--accent);border-radius:5px;transition:width .4s}.server-row{display:flex;justify-content:space-between;gap:18px;align-items:center}.server-info{display:flex;gap:14px;align-items:center}.server-info h3{font-size:17px;margin:0}.server-info p{font-size:13px;color:var(--muted);margin:2px 0}.client{display:grid;grid-template-columns:minmax(180px,.8fr) minmax(160px,.7fr) minmax(0,2fr);align-items:center;gap:12px;padding:16px 0;border-top:1px solid var(--border)}.client:first-child{border-top:0}.client-name{display:flex;align-items:center;gap:10px;font-weight:600;font-size:16px}.client-meta{font-size:12px;color:var(--muted);margin:3px 0 0 19px}.traffic{font-variant-numeric:tabular-nums;color:var(--muted);font-size:13px}.traffic b{color:var(--text);font-weight:500}.actions{display:flex;gap:7px;justify-content:end;align-items:stretch;flex-wrap:nowrap}.actions button,.actions>a,.actions form{height:38px;min-width:84px}.actions button{width:100%;height:38px;padding:6px 8px;font-size:11px;white-space:nowrap}.actions>a{display:flex}.actions>a button{height:38px}.actions form{display:flex;margin:0}.small{font-size:12px;padding:7px 10px}.link{margin-top:10px;padding:11px 13px;border-radius:12px;border:1px solid var(--border);background:var(--input);font:12px/1.5 'IBM Plex Mono',monospace;overflow-wrap:anywhere;color:var(--muted)}.client-lower{grid-column:1/-1;display:grid;grid-template-columns:1fr auto;gap:10px;align-items:center}.qr{width:112px;height:112px;background:white;padding:7px;border-radius:12px;display:none}.qr.open{display:block}.qr-wrap{display:flex;justify-content:end}.form-row{display:flex;gap:9px;flex-wrap:wrap}.form-row input{min-width:210px;flex:1}.sni-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.sni-row input{width:min(350px,100%)}.muted{color:var(--muted)}.pill{font-size:12px;border:1px solid var(--border);border-radius:999px;padding:5px 10px;color:var(--muted);white-space:nowrap}.footer-note{margin-top:14px;color:var(--muted);font-size:12px}.login{max-width:430px;margin:10vh auto}.login input{width:100%;margin:6px 0}.empty{padding:24px;color:var(--muted);text-align:center}.route-grid{display:grid;grid-template-columns:minmax(260px,.85fr) 1.15fr;gap:16px}.route-form{display:flex;gap:8px;flex-wrap:wrap}.route-form input{min-width:180px;flex:1}.route-list{display:grid;gap:7px;margin-top:13px}.route-item{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:9px 11px;border:1px solid var(--border);border-radius:11px;font:13px 'IBM Plex Mono',monospace}.chart-grid{display:grid;grid-template-columns:1fr 1.6fr;gap:14px}.chart-box{min-height:230px}.chart-box h4{margin:0 0 16px;font-size:15px}.donut-wrap{display:flex;align-items:center;gap:20px;justify-content:center}.donut{width:152px;height:152px;border-radius:50%;background:conic-gradient(var(--accent) 0deg,var(--border) 0deg);position:relative;flex:none}.donut:after{content:'';position:absolute;inset:30px;background:var(--card);border-radius:50%}.legend{display:grid;gap:7px;font-size:12px;color:var(--muted)}.legend i{display:inline-block;width:8px;height:8px;background:var(--accent);border-radius:50%;margin-right:6px}.bars{height:170px;display:flex;align-items:end;gap:10px;border-bottom:1px solid var(--border);padding:8px 8px 0;overflow-x:auto}.bar-col{min-width:44px;max-width:90px;flex:1;height:100%;display:flex;flex-direction:column;justify-content:end;align-items:center;gap:5px}.bar-col i{width:min(36px,70%);min-height:2px;background:var(--accent);border-radius:6px 6px 0 0}.bar-col span{max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:10px;color:var(--muted)}.sort-tools{display:flex;gap:8px;align-items:center}.sort-tools select{padding:7px 9px;font-size:12px}.route-setting{display:flex;align-items:center;justify-content:flex-start;gap:8px;margin:0;white-space:nowrap}.route-setting input{margin:0;flex:none}.route-setting-form{align-items:center}.route-setting-form button{flex:none}@media(max-width:1100px){.client{grid-template-columns:minmax(145px,.8fr) minmax(125px,.7fr) minmax(0,1.5fr);gap:8px}.actions{gap:5px}.actions button,.actions>a,.actions form{min-width:74px}.actions button{font-size:10px;padding:5px}}@media(max-width:850px){.grid{grid-template-columns:repeat(2,1fr)}.chart-grid,.route-grid{grid-template-columns:1fr}.client{grid-template-columns:minmax(150px,1fr) auto}.traffic{grid-column:2;grid-row:1}.actions{grid-column:1/-1;grid-row:auto;justify-content:start;flex-wrap:wrap}.actions button,.actions>a,.actions form{min-width:92px}.client-lower{grid-template-columns:1fr auto}}@media(max-width:560px){.shell{padding:22px 14px 45px}.top{margin-bottom:26px}.brand h1{font-size:20px}.brand small{font-size:12px}.hero{align-items:start;flex-direction:column;gap:10px}.hero h2{font-size:25px}.server-row{align-items:start;flex-direction:column}.grid{gap:8px}.card{padding:14px;border-radius:16px}.metric strong{font-size:21px}.client{grid-template-columns:1fr auto;gap:8px}.traffic{grid-column:2;grid-row:1}.actions{flex-direction:row;flex-wrap:wrap}.actions button,.actions>a,.actions form{flex:1 1 44%;min-width:0}.link{font-size:10px}.donut-wrap{justify-content:start}.top-actions>a button{font-size:12px}.section-head{align-items:flex-start;flex-wrap:wrap}}
/* Layout refinements */
@media (prefers-color-scheme:light){body.system{color-scheme:light;--bg:#f2f0eb;--panel:#fff;--card:#fff;--card2:#f8f8f5;--text:#152536;--muted:#64758a;--border:#dce5eb;--accent:#55bdec;--accent2:#269edb;--accent-soft:#e4f5fc;--good:#16a976;--bad:#d74d52;--input:#fff;--shadow:0 10px 28px #2e52640c}}
.route-setting-form{display:flex;align-items:center;justify-content:flex-start;gap:12px}
.route-setting{display:inline-flex;align-items:center;justify-content:flex-start;gap:9px;min-width:0;white-space:normal;cursor:pointer}
.form-row .route-setting input[type=checkbox]{appearance:auto;flex:0 0 18px;min-width:18px;width:18px;height:18px;margin:0;padding:0;accent-color:var(--accent2)}
.route-setting-form button{flex:0 0 auto}
.top-actions{align-items:center}.top-actions button{height:42px;display:inline-flex;align-items:center;justify-content:center}.top-actions>a{display:flex}.top-actions .theme{width:42px;padding:0}
.client{grid-template-columns:minmax(0,1fr) auto}.client>div{min-width:0}.client .actions{grid-column:1/-1;display:grid;grid-template-columns:repeat(5,minmax(0,1fr));align-items:stretch;gap:8px;min-width:0}.actions>button,.actions>a,.actions form{display:flex;width:100%;height:44px;min-width:0;margin:0}.actions button,.actions .action-link{display:flex;align-items:center;justify-content:center;width:100%;height:44px;min-width:0;min-height:44px;padding:6px 8px;border:1px solid var(--border);border-radius:12px;background:var(--card2);color:var(--text);font-size:12px;font-weight:500;line-height:1.2;text-align:center;white-space:normal;cursor:pointer}.actions .danger{color:var(--bad)}.actions button:hover,.actions .action-link:hover{border-color:var(--accent);transform:translateY(-1px)}
.client-lower,.client-lower .link{min-width:0}.client-lower .link{overflow-wrap:anywhere}
@media(max-width:750px){.client .actions{grid-template-columns:repeat(2,minmax(0,1fr))}.client .actions>*:last-child{grid-column:1/-1}}
@media(max-width:420px){.route-setting-form{align-items:flex-start;flex-direction:column}.client{grid-template-columns:1fr}.client .traffic{grid-column:1;grid-row:auto}.client .actions{grid-column:1}.client-lower{grid-template-columns:minmax(0,1fr)}}
.bar-col small{max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:10px;line-height:1.2;color:var(--text);font-variant-numeric:tabular-nums}
.add-status{margin:10px 0 0;color:var(--muted)}.add-status.error{color:var(--bad)}.form-row button:disabled{opacity:.65;cursor:wait;transform:none}
'''
    script='''
const LANG='__LANG__',T={"Работает":"Online","Остановлена":"Stopped","Не в сети":"Offline","Активно":"Active","Сверяем соединение…":"Checking connection…","Панель управления сервером":"Server control panel","Личный сервер":"Private server","Вход в панель":"Sign in","Управление сервером и доступом пользователей":"Manage your server and user access","Логин":"Username","Пароль":"Password","Войти":"Sign in","Неверный логин или пароль":"Incorrect username or password","Обзор сервера":"Server overview","Состояние узла и активность подключений":"Node status and connection activity","обновление каждые 15 сек":"refresh every 15 sec","Нагрузка на процессор":"CPU usage","текущая загрузка CPU":"current CPU usage","Оперативная память":"Memory","Swap":"Swap","Диск":"Disk","Hysteria2":"Hysteria2","Сохранить SNI":"Save SNI","Пользователи":"Users","Индивидуальные подключения и их трафик":"User connections and traffic","всего":"total","Имя нового пользователя":"New username","＋ Добавить пользователя":"＋ Add user","Пока нет пользователей. Добавьте первого выше.":"No users yet. Add the first one above.","Включён":"Enabled","Отключён":"Disabled","Скачать":"Download","Скачано":"Downloaded","Загружено":"Uploaded","Входящий":"Incoming","Исходящий":"Outgoing","QR-код":"QR code","Копировать":"Copy","Отключить":"Disable","Включить":"Enable","Удалить":"Delete","Индикатор показывает текущую сессию Hysteria2. Трафик — накопительно с момента добавления пользователя.":"The indicator shows the current Hysteria2 session. Traffic is cumulative since the user was added.","Смена пароля":"Change password","Введите текущий и новый пароль.":"Enter your current and new password.","Текущий пароль":"Current password","Новый пароль (от 12 символов)":"New password (12+ characters)","Повторите новый пароль":"Confirm new password","Сменить пароль":"Change password","Тема":"Theme","Язык":"Language","Светлая":"Light","Тёмная":"Dark","Русский":"Russian","Английский":"English","Настройки":"Settings","Маршрутизация сайтов":"Site routing","Российские сайты напрямую":"Route Russian sites directly","Включает обход VPN для доменов из списка geosite-ru. Правило действует в экспортируемом профиле sing-box.":"Bypass VPN for domains in the Russian geosite list. This applies to the exported sing-box profile.","Сохранить":"Save","Быстрое исключение":"Quick bypass exception","Добавить домен или IP":"Add domain or IP","Добавить":"Add","Домены и IP, направляемые напрямую":"Domains and IPs routed directly","Пока исключений нет":"No exceptions yet","Статистика трафика пользователей":"User traffic statistics","Доли трафика":"Traffic share","Трафик по пользователям":"Traffic by user","Сортировать":"Sort by","По имени":"Name","По трафику":"Traffic","по возрастанию":"Ascending","по убыванию":"Descending","Получить профиль sing-box":"Get sing-box profile","Обычная Hysteria-ссылка не содержит маршрутизацию. Для правил используйте профиль sing-box.":"A regular Hysteria link does not contain routing rules. Use a sing-box profile to apply these rules.","Правила применяются на устройстве клиента":"Rules are applied on the client device","Профиль включает российские домены и ваши исключения напрямую; остальной трафик идёт через Hysteria.":"The profile routes Russian domains and your exceptions directly; other traffic goes through Hysteria.","Уже существует":"Already exists","Скопировано":"Copied","Переход на главную":"Back to panel","Обновить SNI":"Save SNI"};
Object.assign(T,{"Выйти":"Sign out","Проверяем сервер":"Checking server","Накопленные данные по всем подключениям":"Cumulative data for all connections","Включает обход VPN для доменов и IP России. Правило действует в экспортируемом профиле sing-box.":"Bypass VPN for Russian domains and IPs in the exported sing-box profile.","Неверный домен или IP":"Invalid domain or IP","Назад":"Back","Текущий пароль неверен":"Current password is incorrect","Пароль должен содержать от 12 до 256 символов":"Password must be 12–256 characters","Новые пароли не совпадают":"New passwords do not match","Пароль изменён":"Password changed","Войдите снова с новым паролем.":"Sign in with your new password.","Перейти ко входу":"Go to sign in","Форма устарела":"Form expired","Обновите страницу и добавьте пользователя ещё раз.":"Refresh the page and add the user again.","Вернуться в панель":"Back to panel","Неверное имя пользователя":"Invalid username","Используйте 1–32 латинские буквы, цифры, _ или -.":"Use 1–32 Latin letters, digits, _ or -.","Пользователь уже существует":"User already exists","Выберите другое имя.":"Choose another name.","Нужен хотя бы один активный пользователь":"At least one active user is required","SNI должен совпадать с доменом TLS-сертификата:":"SNI must match the TLS certificate domain:"});
Object.assign(T,{"Направление":"Route","Напрямую":"Direct","Через VPN":"Through VPN","Домен или IP можно направить напрямую или через VPN":"Route a domain or IP directly or through the VPN"});
Object.assign(T,{"Как в системе":"System"});
function translate(){if(LANG!=='en')return;let w=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT),n=[];while(n=w.nextNode()){let k=n.nodeValue.trim();if(T[k])n.nodeValue=n.nodeValue.replace(k,T[k])}document.querySelectorAll('input[placeholder]').forEach(e=>{if(T[e.placeholder])e.placeholder=T[e.placeholder]});document.querySelectorAll('[aria-label]').forEach(e=>{if(T[e.getAttribute('aria-label')])e.setAttribute('aria-label',T[e.getAttribute('aria-label')])});document.querySelectorAll('[title]').forEach(e=>{if(T[e.title])e.title=T[e.title]})}translate();
const themeBtn=document.getElementById('themeToggle');if(themeBtn)themeBtn.onclick=()=>{let v=document.body.classList.contains('light')?'dark':'light';document.cookie='theme='+v+';path=/;max-age=31536000';location.reload()};
const gear=document.getElementById('gearToggle'),settings=document.getElementById('settingsPanel');if(gear&&settings){gear.onclick=()=>settings.hidden=!settings.hidden;document.addEventListener('click',e=>{if(!e.target.closest('.gear-menu'))settings.hidden=true})}const langSel=document.getElementById('languageSelect');if(langSel){langSel.value=LANG;langSel.onchange=()=>{document.cookie='language='+langSel.value+';path=/;max-age=31536000';location.reload()}}const themeSel=document.getElementById('themeSelect');if(themeSel){let savedTheme=document.cookie.match(/(?:^|; )theme=([^;]+)/)?.[1]||'system';themeSel.value=['system','light','dark'].includes(savedTheme)?savedTheme:'system';themeSel.onchange=()=>{document.cookie='theme='+themeSel.value+';path=/;max-age=31536000';location.reload()}};
const passBtn=document.getElementById('passwordToggle'),passForm=document.getElementById('passwordPanel');if(passBtn&&passForm)passBtn.onclick=()=>passForm.hidden=!passForm.hidden;
function fmt(b){if(!Number.isFinite(b))return '—';let value=b/1e6,unit=LANG==='en'?['MB','GB','TB']:['МБ','ГБ','ТБ'],i=0;while(value>=1000&&i<unit.length-1){value/=1000;i++}return value.toFixed(1)+' '+unit[i]}
function refreshCharts(users){let list=Object.entries(users||{}).map(([name,x])=>({name,total:x.tx+x.rx,tx:x.tx,rx:x.rx})).sort((a,b)=>b.total-a.total),sum=list.reduce((n,x)=>n+x.total,0),ring=document.getElementById('trafficDonut'),legend=document.getElementById('trafficLegend'),bars=document.getElementById('trafficBars');if(!ring||!legend||!bars)return;let colors=['var(--accent)','#55bdec','#71cba3','#f0a346','#9d8cf4','#e26f85','#64bbc3'];let at=0,parts=[];list.forEach((x,i)=>{let end=at+(sum?x.total/sum*100:0);parts.push(`${colors[i%colors.length]} ${at}% ${end}%`);at=end});ring.style.background=`conic-gradient(${parts.join(',')||'var(--border) 0 100%'})`;legend.innerHTML=list.length?list.map((x,i)=>`<div><i style="background:${colors[i%colors.length]}"></i>${esc(x.name)} · ${fmt(x.total)}</div>`).join(''):'—';bars.innerHTML=list.map(x=>`<div class="bar-col" title="${esc(x.name)}: ${fmt(x.total)}"><i style="height:${sum?Math.max(2,x.total/Math.max(...list.map(v=>v.total))*100):2}%"></i><span>${esc(x.name)}</span><small title="${LANG==='en'?'Incoming':'Входящий'}: ${fmt(x.rx)}">↓ ${fmt(x.rx)}</small></div>`).join('');}
function esc(s){let d=document.createElement('span');d.textContent=s;return d.innerHTML}
function sortUsers(){let root=document.getElementById('userList'),mode=document.getElementById('sortBy')?.value;if(!root||!mode)return;let nodes=[...root.querySelectorAll('.client')];nodes.sort((a,b)=>{let av=mode==='traffic'?Number(a.dataset.total||0):a.dataset.user.toLowerCase(),bv=mode==='traffic'?Number(b.dataset.total||0):b.dataset.user.toLowerCase();return typeof av==='number'?bv-av:av.localeCompare(bv)});nodes.forEach(n=>root.appendChild(n))}document.getElementById('sortBy')?.addEventListener('change',sortUsers);
const addForm=document.getElementById('addUserForm');if(addForm)addForm.addEventListener('submit',async e=>{e.preventDefault();const input=addForm.elements.u,username=input.value.trim(),button=addForm.querySelector('button'),status=document.getElementById('addStatus'),previous=button.textContent;const existing=[...document.querySelectorAll('.client[data-user]')].some(x=>x.dataset.user.toLowerCase()===username.toLowerCase());if(existing){status.hidden=false;status.classList.add('error');status.textContent=LANG==='en'?'This user already exists.':'Пользователь уже существует.';return}button.disabled=true;button.textContent=LANG==='en'?'Adding…':'Добавляем…';status.hidden=false;status.classList.remove('error');status.textContent=LANG==='en'?'Saving user and updating VPN. The connection may briefly drop; this page will recover automatically.':'Сохраняем пользователя и обновляем VPN. Связь может ненадолго прерваться; страница восстановится сама.';let failure='';fetch(addForm.action,{method:'POST',body:new FormData(addForm),credentials:'same-origin',redirect:'manual'}).then(async r=>{if(r.type!=='opaqueredirect'&&r.status!==302&&r.status!==303){const html=await r.text();failure=new DOMParser().parseFromString(html,'text/html').querySelector('h2')?.textContent|| (LANG==='en'?'Could not add user.':'Не удалось добавить пользователя.')}}).catch(()=>{});const deadline=Date.now()+45000;while(Date.now()<deadline&&!failure){const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),4000);try{const r=await fetch('/api/add-status/'+encodeURIComponent(username),{credentials:'same-origin',cache:'no-store',signal:controller.signal});if(r.ok){const data=await r.json();if(data.status==='ready'){location.replace('/');return}if(data.status==='error'){failure=LANG==='en'?'VPN configuration was not updated. Check the server log.':'Не удалось обновить конфигурацию VPN. Проверьте журнал сервера.';break}}}catch(_){}finally{clearTimeout(timer)}await new Promise(resolve=>setTimeout(resolve,1500))}status.classList.add('error');status.textContent=failure|| (LANG==='en'?'Could not confirm the update. Check whether the user appeared before trying again.':'Не удалось подтвердить обновление. Проверьте, появился ли пользователь, прежде чем повторять попытку.');button.disabled=false;button.textContent=previous});
document.querySelectorAll('form[action="/delete"]').forEach(form=>form.addEventListener('submit',async e=>{e.preventDefault();const username=form.elements.u.value;if(!confirm((LANG==='en'?'Delete user ':'Удалить пользователя ')+username+'?'))return;const button=form.querySelector('button'),meta=form.closest('.client').querySelector('.client-meta'),oldButton=button.textContent,oldMeta=meta.textContent;button.disabled=true;button.textContent=LANG==='en'?'Deleting…':'Удаляем…';meta.setAttribute('role','status');meta.textContent=LANG==='en'?'Removing the connection…':'Отключаем пользователя…';let failure='';fetch(form.action,{method:'POST',body:new FormData(form),credentials:'same-origin',redirect:'manual'}).then(async r=>{if(r.type!=='opaqueredirect'&&r.status!==302&&r.status!==303){const html=await r.text();failure=new DOMParser().parseFromString(html,'text/html').querySelector('h2')?.textContent|| (LANG==='en'?'Could not delete user.':'Не удалось удалить пользователя.')}}).catch(()=>{});const deadline=Date.now()+45000;while(Date.now()<deadline&&!failure){const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),4000);try{const r=await fetch('/api/user-state/'+encodeURIComponent(username),{credentials:'same-origin',cache:'no-store',signal:controller.signal});if(r.ok){const data=await r.json();if(data.delete_status==='ready'&&!data.exists){location.replace('/');return}if(data.delete_status==='error'){failure=LANG==='en'?'Could not complete deletion. Check the server log.':'Не удалось завершить удаление. Проверьте журнал сервера.';break}}}catch(_){}finally{clearTimeout(timer)}await new Promise(resolve=>setTimeout(resolve,1500))}meta.textContent=failure|| (LANG==='en'?'Could not confirm deletion. Check the user list before trying again.':'Не удалось подтвердить удаление. Проверьте список пользователей, прежде чем повторять попытку.');meta.style.color='var(--bad)';button.disabled=false;button.textContent=oldButton}));
function upd(){fetch('/api/metrics').then(r=>r.json()).then(d=>{document.querySelectorAll('[data-metric]').forEach(e=>{let k=e.dataset.metric;if(k in d)e.textContent=d[k]});let a=document.getElementById('serviceLamp');if(a){a.classList.toggle('off',!d.service);document.getElementById('serviceText').textContent=d.service?(LANG==='en'?'Online':'Работает'):(LANG==='en'?'Stopped':'Остановлена');let a2=document.getElementById('serviceLamp2');if(a2)a2.classList.toggle('off',!d.service)}if(d.resources){for(let k of ['ram','swap','disk']){let e=document.getElementById(k+'Bar');if(e)e.style.width=d.resources[k].percent+'%'}}if(d.users){for(let [u,x] of Object.entries(d.users)){let c=document.querySelector('[data-user="'+CSS.escape(u)+'"]');if(!c)continue;let lamp=c.querySelector('.userlamp');lamp.classList.toggle('off',!(x.online>0)||!x.enabled);c.querySelector('[data-traffic="tx"]').textContent=fmt(x.tx);c.querySelector('[data-traffic="rx"]').textContent=fmt(x.rx);c.dataset.total=x.tx+x.rx;let online=c.querySelector('[data-online]');if(online)online.textContent=x.online>0?(LANG==='en'?'Active':'Активно'):(LANG==='en'?'Offline':'Не в сети')}refreshCharts(d.users);sortUsers()}}).catch(()=>{})}upd();setInterval(upd,15000);
function qr(btn){let box=btn.closest('.client').querySelector('.qr');if(!box.dataset.loaded){box.src=btn.dataset.qr;box.dataset.loaded='1'}box.classList.toggle('open')}
function copyLink(btn){navigator.clipboard.writeText(btn.dataset.link);let t=btn.textContent;btn.textContent=LANG==='en'?'Copied':'Скопировано';setTimeout(()=>btn.textContent=t,1300)}
'''.replace('__LANG__',lang)
    html='<!doctype html><html lang="__LANG__"><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Hysteria Control</title><style>__CSS__</style></head><body class="__THEME__"><div class=shell>__BODY__</div><script>__SCRIPT__</script></body></html>'
    html=html.replace('__CSS__',css).replace('__THEME__',theme).replace('__BODY__',body).replace('__SCRIPT__',script).replace('__LANG__',lang)
    return make_response(html)

def logged(): return session.get('ok') is True and session.get('auth_version')==auth_version()
def csrf():
    if 'csrf' not in session: session['csrf']=secrets.token_hex(16)
    return session['csrf']
def valid_csrf():
    token=request.form.get('csrf')
    expected=session.get('csrf')
    return bool(token and expected and secrets.compare_digest(token,expected))
def check():
    if not valid_csrf(): abort(400)

LOGIN='''<div class="top"><div class="brand"><div class=logo>H</div><div><h1>Hysteria Control</h1><small>Личный сервер</small></div></div><div class=top-actions><select id=languageSelect aria-label="Язык"><option value=ru>Русский</option><option value=en>English</option></select><select id=themeSelect aria-label="Тема"><option value=system>Как в системе</option><option value=light>Светлая</option><option value=dark>Тёмная</option></select></div></div><div class="card login"><h2>Вход в панель</h2><p class=muted>Управление сервером и доступом пользователей</p><form method=post><input name=user placeholder="Логин" required><input name=password type=password placeholder="Пароль" required><button class=primary style="width:100%;margin-top:8px">Войти</button></form></div>'''

@app.route('/',methods=['GET','POST'])
def home():
    if request.method=='POST':
        password=request.form.get('password','')
        if request.form.get('user')==os.environ['PANEL_USER'] and admin_password_matches(password):
            if not setting('admin_password_hash'): put_setting('admin_password_hash',hash_password(password))
            session['ok']=True; session['auth_version']=auth_version(); return redirect('/')
        return page(LOGIN.replace('Личный сервер','Неверный логин или пароль'))
    if not logged(): return page(LOGIN)
    c=conn(); users=c.execute('select username,password,enabled from users order by username').fetchall(); c.close()
    sni=setting('sni',DOMAIN); tok=csrf()
    selected='en' if request.cookies.get('language')=='en' else 'ru'
    theme=request.cookies.get('theme','system')
    if theme not in ('system','light','dark'): theme='system'
    settings_menu=f'''<div class=gear-menu><button class="theme icon-button" type=button id=gearToggle title="Настройки" aria-label="Настройки" aria-controls=settingsPanel>⚙</button><div class="card gear-popover" id=settingsPanel hidden><h3>Настройки</h3><div class=setting-line><span>Тема</span><select id=themeSelect aria-label="Тема"><option value=system {'selected' if theme=='system' else ''}>Как в системе</option><option value=light {'selected' if theme=='light' else ''}>Светлая</option><option value=dark {'selected' if theme=='dark' else ''}>Тёмная</option></select></div><div class=setting-line><span>Язык</span><select id=languageSelect aria-label="Язык"><option value=ru {'selected' if selected=='ru' else ''}>Русский</option><option value=en {'selected' if selected=='en' else ''}>English</option></select></div><div class=setting-line><button type=button id=passwordToggle>Сменить пароль</button></div><div class=password-popover id=passwordPanel hidden><h4>Смена пароля</h4><form method=post action=/password><input type=hidden name=csrf value="{tok}"><input type=password name=current_password placeholder="Текущий пароль" autocomplete=current-password required><input type=password name=new_password placeholder="Новый пароль (от 12 символов)" autocomplete=new-password minlength=12 maxlength=256 required><input type=password name=confirm_password placeholder="Повторите новый пароль" autocomplete=new-password minlength=12 maxlength=256 required><button class=primary>Сменить пароль</button></form></div></div></div>'''
    body=f'''<header class=top><div class=brand><div class=logo>H</div><div><h1>Hysteria Control</h1><small>Панель управления сервером</small></div></div><div class=top-actions>{settings_menu}<a href=/logout><button>Выйти</button></a></div></header>
<div class=hero><div><h2>Обзор сервера</h2><p>Состояние узла и активность подключений</p></div><div class=live><span class="lamp" id=serviceLamp></span><span id=serviceText>Проверяем сервер</span><span class=pill>обновление каждые 15 сек</span></div></div>
<div class=grid><div class="card metric"><div class=label>Нагрузка на процессор</div><strong><span data-metric=cpu>—</span></strong><div class=sub>текущая загрузка CPU</div></div><div class="card metric"><div class=label>Оперативная память</div><strong><span data-metric=ram>—</span></strong><div class=bar><i id=ramBar></i></div></div><div class="card metric"><div class=label>Swap</div><strong><span data-metric=swap>—</span></strong><div class=bar><i id=swapBar></i></div></div><div class="card metric"><div class=label>Диск</div><strong><span data-metric=disk>—</span></strong><div class=bar><i id=diskBar></i></div></div></div>
<section class="card server-card"><div class=server-row><div class=server-info><span class=lamp id=serviceLamp2></span><div><h3>Hysteria2</h3><p>UDP/443 · {DOMAIN}</p></div></div><form method=post action=/sni><input type=hidden name=csrf value="{tok}"><div class=sni-row><input name=sni value="{sni}" aria-label="SNI"><button class=small>Сохранить SNI</button></div></form></div></section>
<div class=section-head><div><h3>Статистика трафика пользователей</h3><p>Накопленные данные по всем подключениям</p></div></div>
<div class=chart-grid><section class="card chart-box"><h4>Доли трафика</h4><div class=donut-wrap><div class=donut id=trafficDonut role=img aria-label="Доли трафика"></div><div class=legend id=trafficLegend>—</div></div></section><section class="card chart-box"><h4>Трафик по пользователям</h4><div class=bars id=trafficBars></div></section></div>
'''
    body+=f'''<div class=section-head><div><h3>Пользователи</h3><p>Индивидуальные подключения и их трафик</p></div><div class=sort-tools><select id=sortBy aria-label="Сортировать"><option value=name>По имени</option><option value=traffic>По трафику</option></select><span class=pill>{len(users)} <span>всего</span></span></div></div>
<section class=card><form id=addUserForm class=form-row method=post action=/add><input type=hidden name=csrf value="{tok}"><input name=u placeholder="Имя нового пользователя" pattern="[A-Za-z0-9_-]{{1,32}}" maxlength=32 required><button class=primary>＋ Добавить пользователя</button></form><p id=addStatus class=add-status role=status aria-live=polite hidden></p><div id=userList style="margin-top:14px">'''
    if not users: body+='<div class=empty>Пока нет пользователей. Добавьте первого выше.</div>'
    for u in users:
        name=u['username']; uri=f'hysteria2://{name}:{u["password"]}@{DOMAIN}:443/?sni={sni}&insecure=0#{name}'
        state='Включён' if u['enabled'] else 'Отключён'
        qrurl='/qr/'+urllib.parse.quote(name,safe='')
        body+=f'''<div class=client data-user="{name}"><div><div class=client-name><span class="lamp userlamp {'off' if not u['enabled'] else ''}"></span>{name}<span class=pill>{state}</span></div><div class=client-meta data-online>Сверяем соединение…</div></div><div class=traffic><span>Входящий:</span> <b data-traffic=rx>—</b><br><span>Исходящий:</span> <b data-traffic=tx>—</b></div><div class=actions><button type=button class=small onclick="qr(this)" data-qr="{qrurl}">QR-код</button><button type=button class=small onclick="copyLink(this)" data-link="{uri}">Копировать</button><form method=post action=/toggle><input type=hidden name=csrf value="{tok}"><input type=hidden name=u value="{name}"><button class="small">{'Отключить' if u['enabled'] else 'Включить'}</button></form><form method=post action=/delete><input type=hidden name=csrf value="{tok}"><input type=hidden name=u value="{name}"><button class="small danger">Удалить</button></form></div><div class=client-lower><div class=link>{uri}</div><div class=qr-wrap><img class=qr alt="QR код подключения"></div></div></div>'''
    body+='''</div></section><div class=footer-note>Индикатор показывает текущую сессию Hysteria2. Трафик — накопительно с момента добавления пользователя.</div>'''
    return page(body)

@app.route('/password',methods=['GET','POST'])
def change_password():
    if request.method=='GET': return redirect('/')
    if not logged(): abort(403)
    check()
    current=request.form.get('current_password','')
    new=request.form.get('new_password','')
    confirm=request.form.get('confirm_password','')
    if not admin_password_matches(current):
        return page('<div class="card login"><h2>Текущий пароль неверен</h2><a href="/"><button>Назад</button></a></div>')
    if len(new)<12 or len(new)>256:
        return page('<div class="card login"><h2>Пароль должен содержать от 12 до 256 символов</h2><a href="/"><button>Назад</button></a></div>')
    if not secrets.compare_digest(new,confirm):
        return page('<div class="card login"><h2>Новые пароли не совпадают</h2><a href="/"><button>Назад</button></a></div>')
    put_setting('admin_password_hash',hash_password(new))
    put_setting('admin_auth_version',secrets.token_urlsafe(24))
    session.clear()
    return page('<div class="card login"><h2>Пароль изменён</h2><p class=muted>Войдите снова с новым паролем.</p><a href="/"><button class=primary>Перейти ко входу</button></a></div>')

@app.route('/add',methods=['GET','POST'])
def add():
    if request.method=='GET': return redirect('/')
    if not logged(): abort(403)
    if not valid_csrf():
        return page('<div class="card login"><h2>Форма устарела</h2><p class=muted>Обновите страницу и добавьте пользователя ещё раз.</p><a href="/"><button>Вернуться в панель</button></a></div>')
    u=request.form.get('u','').strip()
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,32}',u):
        return page('<div class="card login"><h2>Неверное имя пользователя</h2><p class=muted>Используйте 1–32 латинские буквы, цифры, _ или -.</p><a href="/"><button>Вернуться в панель</button></a></div>')
    c=conn()
    if c.execute('select 1 from users where username=? collate nocase',(u,)).fetchone():
        c.close(); return page('<div class="card login"><h2>Пользователь уже существует</h2><p class=muted>Выберите другое имя.</p><a href="/"><button>Вернуться в панель</button></a></div>')
    try: c.execute('insert into users(username,password,enabled) values(?,?,1)',(u,secrets.token_urlsafe(20))); c.commit()
    except sqlite3.IntegrityError:
        c.close(); return page('<div class="card login"><h2>Пользователь уже существует</h2><p class=muted>Выберите другое имя.</p><a href="/"><button>Вернуться в панель</button></a></div>')
    c.close()
    with add_states_lock: add_states[u]='pending'
    try: sync()
    except Exception:
        with add_states_lock: add_states[u]='error'
        raise
    with add_states_lock: add_states[u]='ready'
    return redirect('/')

@app.get('/api/add-status/<username>')
def add_status(username):
    if not logged(): abort(403)
    with add_states_lock: status=add_states.get(username,'unknown')
    return {'status':status}
@app.route('/toggle',methods=['GET','POST'])
def toggle():
    if request.method=='GET': return redirect('/')
    if not logged(): abort(403)
    check(); username=request.form.get('u'); c=conn()
    target=c.execute('select enabled from users where username=?',(username,)).fetchone()
    if target and target['enabled'] and c.execute('select count(*) from users where enabled=1').fetchone()[0]<=1:
        c.close(); return page('<div class="card login"><h2>Нужен хотя бы один активный пользователь</h2><a href="/"><button>Назад</button></a></div>')
    if target and target['enabled']:
        c.close(); record_traffic(); c=conn()
    c.execute('update users set enabled=1-enabled where username=?',(username,)); c.commit(); c.close()
    sync()
    if DYNAMIC_AUTH and target and target['enabled']: kick_user(username)
    return redirect('/')
@app.route('/delete',methods=['GET','POST'])
def delete():
    if request.method=='GET': return redirect('/')
    if not logged(): abort(403)
    check(); username=request.form.get('u'); record_traffic(); c=conn()
    target=c.execute('select enabled from users where username=?',(username,)).fetchone()
    if target and target['enabled'] and c.execute('select count(*) from users where enabled=1').fetchone()[0]<=1:
        c.close(); return page('<div class="card login"><h2>Нужен хотя бы один активный пользователь</h2><a href="/"><button>Назад</button></a></div>')
    c.execute('delete from users where username=?',(username,)); c.commit(); c.close()
    with add_states_lock: delete_states[username]='pending'
    try:
        sync()
        if DYNAMIC_AUTH and target: kick_user(username)
    except Exception:
        with add_states_lock: delete_states[username]='error'
        raise
    with add_states_lock: delete_states[username]='ready'
    return redirect('/')

@app.get('/api/user-state/<username>')
def user_state(username):
    if not logged(): abort(403)
    c=conn(); user=c.execute('select enabled from users where username=?',(username,)).fetchone(); c.close()
    with add_states_lock: status=delete_states.get(username,'unknown')
    return {'exists':bool(user),'enabled':bool(user['enabled']) if user else False,'delete_status':status}
@app.route('/sni',methods=['GET','POST'])
def sni():
    if request.method=='GET': return redirect('/')
    if not logged(): abort(403)
    check(); value=request.form.get('sni','').strip().lower()
    if value!=DOMAIN: return page('<div class="card">SNI должен совпадать с доменом TLS-сертификата: '+DOMAIN+'.</div><a href="/"><button>Назад</button></a>')
    put_setting('sni',value); return redirect('/')

@app.get('/fonts/<path:filename>')
def fonts(filename):
    if filename not in {'ibm-plex-sans-cyrillic.woff2','ibm-plex-sans-latin.woff2','ibm-plex-mono-cyrillic.woff2','ibm-plex-mono-latin.woff2'}: abort(404)
    return send_from_directory(os.path.join(os.path.dirname(__file__),'assets','fonts'),filename,max_age=604800)

@app.get('/qr/<username>')
def qr(username):
    if not logged(): abort(403)
    c=conn(); u=c.execute('select username,password,enabled from users where username=?',(username,)).fetchone(); c.close()
    if not u: abort(404)
    uri=f'hysteria2://{username}:{u["password"]}@{DOMAIN}:443/?sni={setting("sni",DOMAIN)}&insecure=0#{username}'
    p=subprocess.run(['qrencode','-t','PNG','-o','-','-s','6','-m','2'],input=uri.encode(),capture_output=True,check=True)
    return Response(p.stdout,mimetype='image/png',headers={'Cache-Control':'no-store'})

def cpu_counters():
    a=list(map(int,open('/proc/stat').readline().split()[1:])); return sum(a),sum(a[3:5])
def resources():
    global last_cpu,last_net,last_sample
    m={}
    for line in open('/proc/meminfo'):
        k,v=line.split(':',1); m[k]=int(v.strip().split()[0])
    total=m.get('MemTotal',0); avail=m.get('MemAvailable',0); st=m.get('SwapTotal',0); sf=m.get('SwapFree',0)
    d=subprocess.check_output(['df','-Pk','/'],text=True).splitlines()[1].split(); du,dt=int(d[2]),int(d[1])
    cpu=cpu_counters()
    if last_cpu is None:
        time.sleep(0.1)
        last_cpu=cpu
        cpu=cpu_counters()
    total_delta=cpu[0]-last_cpu[0]
    idle_delta=cpu[1]-last_cpu[1]
    cpu_pct=max(0,min(100,100*(1-idle_delta/max(1,total_delta))))
    last_cpu=cpu
    mb='MB' if request.cookies.get('language')=='en' else 'МБ'
    result={'cpu':f'{cpu_pct:.0f}%', 'ram':f'{(total-avail)/1024:.0f} / {total/1024:.0f} {mb}','swap':f'{(st-sf)/1024:.0f} / {st/1024:.0f} {mb}','disk':f'{du/1024:.0f} / {dt/1024:.0f} {mb}','resources':{'ram':{'percent':round(100*(total-avail)/max(1,total))},'swap':{'percent':round(100*(st-sf)/max(1,st))},'disk':{'percent':int(d[4].rstrip('%'))}}}
    return result
@app.get('/api/metrics')
def metrics():
    if not logged(): abort(403)
    data=resources()
    try: online=api_get('/online'); record_traffic(); data['service']=True
    except Exception: online={}; data['service']=False
    c=conn(); rows=c.execute('select u.username,u.enabled,coalesce(s.tx,0),coalesce(s.rx,0) from users u left join usage s using(username)').fetchall(); c.close()
    online_by_name={str(name).lower():int(count) for name,count in online.items()}
    data['users']={r['username']:{'online':online_by_name.get(r['username'].lower(),0) if r['enabled'] else 0,'tx':int(r[2]),'rx':int(r[3]),'enabled':bool(r['enabled'])} for r in rows}
    return data
@app.get('/logout')
def logout(): session.clear(); return redirect('/')

class PanelServer(ThreadedWSGIServer):
    """Keep a slow TLS handshake from blocking the listening socket."""
    daemon_threads=True
    max_connections=32

    def __init__(self):
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(PANEL_CERT,PANEL_KEY)
        # Werkzeug normally wraps the listening socket. Its accept loop then
        # waits for each TLS handshake before it can accept another client.
        super().__init__('0.0.0.0',PANEL_PORT,app)
        self.ssl_context=context
        self.connections=threading.BoundedSemaphore(self.max_connections)

    def process_request(self,request,client_address):
        if not self.connections.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request,client_address)
        except BaseException:
            request.close()
            self.connections.release()
            raise

    def process_request_thread(self,request,client_address):
        secure=None
        try:
            request.settimeout(5)
            secure=self.ssl_context.wrap_socket(request,server_side=True)
            secure.settimeout(30)
            self.finish_request(secure,client_address)
        except OSError:
            # A client can disconnect during the handshake or response.
            pass
        except Exception:
            self.handle_error(request,client_address)
        finally:
            self.shutdown_request(secure if secure is not None else request)
            self.connections.release()

if __name__=='__main__':
    if sys.argv[1:]==['--sync-root']:
        write_server_config()
    else:
        auth_server=ThreadingHTTPServer(('127.0.0.1',AUTH_PORT),HysteriaAuthHandler)
        auth_server.daemon_threads=True
        threading.Thread(target=auth_server.serve_forever,daemon=True).start()
        server=PanelServer()
        try: server.serve_forever()
        finally:
            server.server_close()
            auth_server.shutdown()
            auth_server.server_close()
