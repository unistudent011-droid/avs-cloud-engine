import os, sys, json, time, shutil, zipfile, subprocess, urllib.parse, urllib.request
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

class NoAuthRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return urllib.request.Request(newurl, headers={"User-Agent": "AIVideoStudio-Cloud"})

def download_github_asset(asset_url, gh_token, dest):
    opener = urllib.request.build_opener(NoAuthRedirectHandler)
    for attempt in range(6):
        req = urllib.request.Request(
            asset_url,
            headers={
                "Authorization": f"Bearer {gh_token}",
                "Accept": "application/octet-stream",
                "User-Agent": "AIVideoStudio-Cloud",
            },
        )
        try:
            with opener.open(req, timeout=300) as r, open(dest, "wb") as f:
                shutil.copyfileobj(r, f)
            return
        except Exception:
            if attempt < 5:
                time.sleep(3 * (attempt + 1))
                continue
            raise

def get_access_token(dcfg):
    data = urllib.parse.urlencode({
        "client_id": dcfg["client_id"],
        "client_secret": dcfg["client_secret"],
        "refresh_token": dcfg["refresh_token"],
        "grant_type": "refresh_token",
    }).encode("utf-8")
    for attempt in range(8):
        req = urllib.request.Request("https://oauth2.googleapis.com/token", data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read().decode("utf-8"))["access_token"]
        except Exception:
            if attempt < 7:
                time.sleep(3)
                continue
            raise

def download_drive_file(token, file_id, dest):
    for attempt in range(24):
        req = urllib.request.Request(f"https://www.googleapis.com/drive/v3/files/{file_id}?alt=media", headers={"Authorization": f"Bearer {token}"})
        try:
            with urllib.request.urlopen(req, timeout=300) as r, open(dest, "wb") as f:
                shutil.copyfileobj(r, f)
            return
        except Exception as e:
            if attempt < 23 and getattr(e, "code", None) in (403, 429, 500, 502, 503, 504):
                time.sleep(4)
                continue
            raise

def delete_drive_file(token, file_id):
    if not token or not file_id:
        return
    try:
        req = urllib.request.Request(f"https://www.googleapis.com/drive/v3/files/{file_id}", headers={"Authorization": f"Bearer {token}"}, method="DELETE")
        with urllib.request.urlopen(req, timeout=20):
            pass
    except Exception:
        pass

def _deobf(s):
    if isinstance(s, str) and s.startswith("OBF:"):
        import base64
        return base64.b64decode(s[4:].encode("ascii")).decode("utf-8")[::-1]
    return s or ""

def _avs_stream_xor(data_bytes, enc_key, salt_bytes):
    import hashlib
    out = bytearray(len(data_bytes))
    mv = memoryview(data_bytes)
    off = 0
    ctr = 0
    n = len(data_bytes)
    while off < n:
        blk = hashlib.sha256(enc_key + salt_bytes + ctr.to_bytes(8, "big")).digest()
        take = min(32, n - off)
        for i in range(take):
            out[off + i] = mv[off + i] ^ blk[i]
        off += take
        ctr += 1
    return bytes(out)

def _encrypt_payload_bytes(raw_bytes):
    import hashlib, hmac, base64
    skey = (os.environ.get("AVS_SECRET_KEY") or "").strip()
    if not skey:
        return raw_bytes
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", skey.encode("utf-8"), salt, 10000, dklen=64)
    enc_k, mac_k = dk[:32], dk[32:]
    ct = _avs_stream_xor(raw_bytes, enc_k, salt)
    mac = hmac.new(mac_k, salt + ct, hashlib.sha256).hexdigest()
    return json.dumps({"encrypted": True, "v": 1, "salt": salt.hex(), "data": base64.b64encode(ct).decode("ascii"), "mac": mac}, indent=2).encode("utf-8")

def _decrypt_payload_doc(doc):
    import hashlib, hmac, base64
    if not isinstance(doc, dict) or not doc.get("encrypted"):
        return doc
    skey = (os.environ.get("AVS_SECRET_KEY") or "").strip()
    if not skey:
        raise RuntimeError("Encrypted cloud job requires AVS_SECRET_KEY in GitHub Repository Secrets")
    salt = bytes.fromhex(doc["salt"])
    ct = base64.b64decode(doc["data"].encode("ascii"))
    dk = hashlib.pbkdf2_hmac("sha256", skey.encode("utf-8"), salt, 10000, dklen=64)
    enc_k, mac_k = dk[:32], dk[32:]
    exp_mac = hmac.new(mac_k, salt + ct, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(exp_mac, str(doc.get("mac") or "")):
        raise RuntimeError("Encrypted cloud job HMAC verification failed")
    pt = _avs_stream_xor(ct, enc_k, salt)
    return json.loads(pt.decode("utf-8"))

def main():
    job_id = sys.argv[1]
    with open(f"jobs/{job_id}.json", "r", encoding="utf-8") as f:
        job = _decrypt_payload_doc(json.load(f))
    dcfg = job["drive"]
    work = os.path.abspath("avs_work")
    os.makedirs(work, exist_ok=True)
    rt_zip = os.path.join(work, "runtime.zip")
    gh_rt = job.get("github_runtime") or {}
    rt_tok = _deobf(gh_rt.get("token_obf") or gh_rt.get("token"))
    rt_downloaded = False
    if job.get("runtime_file_id"):
        try:
            print("[AVS-CLOUD] Downloading runtime from Google Drive (Primary Anti-Ban)...", flush=True)
            token = get_access_token(dcfg)
            download_drive_file(token, job["runtime_file_id"], rt_zip)
            if os.path.isfile(rt_zip) and os.path.getsize(rt_zip) > 10 * 1024 * 1024:
                rt_downloaded = True
        except Exception as e:
            print("[AVS-CLOUD] Google Drive runtime download warn, trying GitHub fallback:", e, flush=True)
    if not rt_downloaded and gh_rt.get("asset_url") and rt_tok:
        try:
            print("[AVS-CLOUD] Downloading runtime from GitHub Release Asset...", flush=True)
            download_github_asset(gh_rt["asset_url"], rt_tok, rt_zip)
            if os.path.isfile(rt_zip) and os.path.getsize(rt_zip) > 10 * 1024 * 1024:
                rt_downloaded = True
        except Exception as e:
            print("[AVS-CLOUD] GitHub Release runtime download warn:", e, flush=True)
    if not rt_downloaded:
        raise RuntimeError("Failed to download runtime.zip from both Google Drive and GitHub Release")

    with zipfile.ZipFile(rt_zip, "r") as zf:
        zf.extractall(work)
    if job.get("runtime_patch_id"):
        try:
            print("[AVS-CLOUD] Applying latest runtime patch...", flush=True)
            p_zip = os.path.join(work, "runtime_patch.zip")
            ptok = get_access_token(dcfg)
            download_drive_file(ptok, job["runtime_patch_id"], p_zip)
            if os.path.isfile(p_zip) and os.path.getsize(p_zip) > 100:
                with zipfile.ZipFile(p_zip, "r") as pzf:
                    pzf.extractall(work)
                print("[AVS-CLOUD] Runtime patch applied OK!", flush=True)
        except Exception as pe:
            print("[AVS-CLOUD] Runtime patch warn:", pe, flush=True)
    bin_dir = os.path.join(work, "bin")
    os.makedirs(bin_dir, exist_ok=True)
    for exe_name in ("ffmpeg.exe", "ffprobe.exe"):
        sys_exe = shutil.which(exe_name)
        if sys_exe and not os.path.isfile(os.path.join(bin_dir, exe_name)):
            shutil.copy(sys_exe, os.path.join(bin_dir, exe_name))
    if not os.path.isfile(os.path.join(bin_dir, "ffmpeg.exe")) or not os.path.isfile(os.path.join(bin_dir, "ffprobe.exe")):
        print("[AVS-CLOUD] Installing FFmpeg into bin/ from GitHub Releases...", flush=True)
        ff_zip = os.path.join(work, "ffmpeg_win64.zip")
        for ff_url in (
            "https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/ffmpeg-master-latest-win64-gpl.zip",
            "https://github.com/GyanD/codexffmpeg/releases/download/7.1.1/ffmpeg-7.1.1-essentials_build.zip",
        ):
            try:
                req = urllib.request.Request(ff_url, headers={"User-Agent": "AIVideoStudio-Cloud"})
                with urllib.request.urlopen(req, timeout=180) as r, open(ff_zip, "wb") as f:
                    shutil.copyfileobj(r, f)
                with zipfile.ZipFile(ff_zip, "r") as zf:
                    for member in zf.namelist():
                        base_m = os.path.basename(member).lower()
                        if base_m in ("ffmpeg.exe", "ffprobe.exe"):
                            with zf.open(member) as src_f, open(os.path.join(bin_dir, base_m), "wb") as dst_f:
                                shutil.copyfileobj(src_f, dst_f)
                if os.path.isfile(os.path.join(bin_dir, "ffmpeg.exe")) and os.path.isfile(os.path.join(bin_dir, "ffprobe.exe")):
                    break
            except Exception as e:
                print("[AVS-CLOUD] FFmpeg zip download warn:", e, flush=True)
        if os.path.isfile(ff_zip):
            try:
                os.remove(ff_zip)
            except Exception:
                pass
    if not os.path.isfile(os.path.join(bin_dir, "ffmpeg.exe")):
        try:
            subprocess.run(["choco", "install", "ffmpeg", "-y", "--no-progress"], check=False)
            for exe_name in ("ffmpeg.exe", "ffprobe.exe"):
                sys_exe = shutil.which(exe_name) or os.path.join(r"C:\ProgramData\chocolatey\bin", exe_name)
                if os.path.isfile(sys_exe) and not os.path.isfile(os.path.join(bin_dir, exe_name)):
                    shutil.copy(sys_exe, os.path.join(bin_dir, exe_name))
        except Exception:
            pass
    os.environ["PATH"] = bin_dir + os.pathsep + (os.environ.get("PATH") or "")
    print("[AVS-CLOUD] FFmpeg ready:", os.path.isfile(os.path.join(bin_dir, "ffmpeg.exe")), shutil.which("ffmpeg"), flush=True)

    app_data = os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~\\AppData\\Local"), "AI Video Studio")
    os.makedirs(app_data, exist_ok=True)
    local_repo_st = f"jobs/{job_id}_state.zip"
    st_zip = os.path.join(work, "state.zip")
    st_downloaded = False
    if job.get("db_file_id"):
        try:
            print("[AVS-CLOUD] Downloading state.zip from Google Drive...", flush=True)
            token = get_access_token(dcfg)
            download_drive_file(token, job["db_file_id"], st_zip)
            if os.path.isfile(st_zip) and os.path.getsize(st_zip) > 100:
                st_downloaded = True
                if not job.get("shared_state"):
                    delete_drive_file(token, job["db_file_id"])
                    print("[AVS-CLOUD] Cleaned up temporary state.zip from Google Drive (0 MB wasted)!", flush=True)
                else:
                    print("[AVS-CLOUD] Using shared cached state.zip on Google Drive.", flush=True)
        except Exception as e:
            print("[AVS-CLOUD] Google Drive state.zip download warn:", e, flush=True)
    if not st_downloaded and os.path.isfile(local_repo_st):
        print("[AVS-CLOUD] Extracting state.zip from checked-out GitHub repository...", flush=True)
        shutil.copy(local_repo_st, st_zip)

    with zipfile.ZipFile(st_zip, "r") as szf:
        szf.extractall(app_data)

    ckpt_dir = os.path.join(work, "checkpoint_restore")
    if job.get("checkpoint_file_id"):
        try:
            print("[AVS-CLOUD] Downloading resume checkpoint from Google Drive...", flush=True)
            ckpt_zip = os.path.join(work, "checkpoint.zip")
            ctok = get_access_token(dcfg)
            download_drive_file(ctok, job["checkpoint_file_id"], ckpt_zip)
            if os.path.isfile(ckpt_zip) and os.path.getsize(ckpt_zip) > 100:
                os.makedirs(ckpt_dir, exist_ok=True)
                with zipfile.ZipFile(ckpt_zip, "r") as czf:
                    czf.extractall(ckpt_dir)
                delete_drive_file(ctok, job["checkpoint_file_id"])
                print("[AVS-CLOUD] Checkpoint restored & cleaned from Google Drive!", flush=True)
        except Exception as ce:
            print("[AVS-CLOUD] Checkpoint download warn:", ce, flush=True)

    sc_latest = os.path.join(app_data, "sitecustomize_latest.py")
    if os.path.isfile(sc_latest):
        shutil.copy(sc_latest, os.path.join(work, "python", "Lib", "site-packages", "sitecustomize.py"))
    with open(os.path.join(app_data, "cloud_drive_config.json"), "w", encoding="utf-8") as cf:
        json.dump({"drive": job.get("upload_drive") or dcfg}, cf)
    with open(os.path.join(work, "job_meta.json"), "w", encoding="utf-8") as jf:
        json.dump(job, jf)

    run_code = """import os, sys, json, time, base64, sqlite3, shutil
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
os.environ['AVS_IS_CLOUD_WORKER'] = '1'
_bin_d = os.path.join(os.getcwd(), 'bin')
if os.path.isdir(_bin_d) and _bin_d.lower() not in (os.environ.get('PATH') or '').lower():
    os.environ['PATH'] = _bin_d + os.pathsep + (os.environ.get('PATH') or '')
sys.path.insert(0, os.getcwd())
import sitecustomize, app.secrets as sec, app.main as m, app.db as db, app.llm as llm, app.runner as r

# 1. Ensure sitecustomize patches are applied once on Cloud Worker
if not getattr(sitecustomize, '_PATCHED', False):
    sitecustomize._apply_patches()
if not getattr(sitecustomize, '_PATCHED_DIALOGUE', False):
    sitecustomize._apply_dialogue_patches()

# 2. Re-encrypt portable AVS_RAW secrets with Cloud Worker's native Windows DPAPI
c = sqlite3.connect(db.DB_PATH)
for tbl in ('agy_accounts', 'keys'):
    try:
        for rid, sblob in c.execute(f'SELECT id, secret FROM {tbl}').fetchall():
            b_raw = bytes.fromhex(sblob) if isinstance(sblob, str) else bytes(sblob)
            if b_raw.startswith(b'AVS_RAW:'):
                plain = b_raw[8:].decode('utf-8', 'replace')
            else:
                plain = sec.unprotect(b_raw)
            if isinstance(plain, str) and plain:
                c.execute(f'UPDATE {tbl} SET secret = ? WHERE id = ?', (sec.protect(plain), rid))
    except Exception as e:
        print(f'[AVS-CLOUD] Secret re-protect warn ({tbl}):', e, flush=True)
c.commit()
c.close()

# 3. Initialize all modules & set Cloud output folder
db.init()
m.agy_accounts.init()
m.keys.init()
m.google.init()
s = db.get_settings()
out_dir = os.path.join(os.getcwd(), 'output_videos')
os.makedirs(out_dir, exist_ok=True)
s['folder'] = out_dir
db.save_settings(s)

# 4. Ensure Antigravity CLI is installed
try:
    if not llm.agy_exe():
        print('[AVS-CLOUD] Downloading Antigravity CLI...', flush=True)
        llm._agy_download()
    print('[AVS-CLOUD] Antigravity CLI:', llm.agy_exe(), 'Ready AGY:', m.agy_accounts.count_ready(), 'Google Pro:', len(m.google.ready_rows()), 'Groq keys:', len(m.keys.usable('groq')), flush=True)
except Exception as e:
    print('[AVS-CLOUD] AGY CLI setup warn:', e, flush=True)

# 5. Create batch via m.new_batch so all Niche defaults & options apply identically to local PC
# Disable internal runner.wake() on Cloud Worker so ONLY _drive_cloud_steps drives each step once without racing!
r.wake = lambda *a, **k: None
job_meta = json.load(open('job_meta.json', 'r', encoding='utf-8'))
b = job_meta['batch']
opts = b.get('options') or {}
opts['cloudMode'] = False
opts['saveToDrive'] = True
opts['cleanLocalAfterDrive'] = False
b['options'] = opts
if b.get('topic') and not b.get('topics'):
    b['topics'] = [str(b.pop('topic')).strip()]
if b.get('script') and not b.get('scripts'):
    b['scripts'] = [str(b.pop('script')).strip()]
for _lk in ('links', 'topics', 'scripts'):
    _lv = b.get(_lk)
    if isinstance(_lv, str):
        _lv_s = _lv.strip()
        if _lk == 'links' and _lv_s.startswith('topic:') and not b.get('topics'):
            b['topics'] = [_lv_s[6:].strip()]
            b['links'] = []
        elif _lk == 'links' and _lv_s.startswith('script:') and not b.get('scripts'):
            b['scripts'] = [_lv_s[7:].strip()]
            b['links'] = []
        else:
            b[_lk] = [_lv_s] if _lv_s else []
    elif isinstance(_lv, (list, tuple)):
        b[_lk] = [str(x).strip() for x in _lv if str(x or '').strip()]
    elif _lv is None:
        b[_lk] = []

_JOB_START_TS = time.time()
_HANDOFF_AGE_SEC = 5 * 3600 + 20 * 60
_ckpt_db_src = os.path.join(os.getcwd(), 'checkpoint_restore', 'studio.db')
if os.path.isfile(_ckpt_db_src):
    shutil.copy2(_ckpt_db_src, db.DB_PATH)
    _ckpt_vdir = os.path.join(os.getcwd(), 'checkpoint_restore', 'videos')
    for _vr in db.videos():
        _vfd = _vr.get('folder') or ''
        _src_vf = os.path.join(_ckpt_vdir, _vr['id'])
        if _vfd and os.path.isdir(_src_vf):
            os.makedirs(_vfd, exist_ok=True)
            for _rt_d, _, _fs_l in os.walk(_src_vf):
                _rel_d = os.path.relpath(_rt_d, _src_vf)
                _dst_d = _vfd if _rel_d == '.' else os.path.join(_vfd, _rel_d)
                os.makedirs(_dst_d, exist_ok=True)
                for _fn in _fs_l:
                    shutil.copy2(os.path.join(_rt_d, _fn), os.path.join(_dst_d, _fn))
    bid = (db.videos()[0].get('batch_id') if db.videos() else None)
    print('[AVS-CLOUD] Resumed batch from checkpoint:', bid, flush=True)
else:
    nb_res = m.new_batch(m.NewBatch(**b))
    bid = nb_res.get('id') if isinstance(nb_res, dict) else None
    print('[AVS-CLOUD] Created batch:', bid, flush=True)

STEP_NAMES = ['Download', 'Summary', 'Script', 'Voice', 'Scenes', 'Pictures', 'Render', 'Title and thumbnails']
srv_num = job_meta.get('server_number', 1)
srv_owner = job_meta.get('status_owner', '')
srv_repo = job_meta.get('status_repo', 'avs-cloud-worker')
_raw_st = job_meta.get('status_token_obf') or job_meta.get('status_token') or ''
srv_token = base64.b64decode(_raw_st[4:].encode('ascii')).decode('utf-8')[::-1] if isinstance(_raw_st, str) and _raw_st.startswith('OBF:') else _raw_st
job_id = job_meta.get('job_id', '')
status_file_id = job_meta.get('status_file_id') or ''
drive_cfg = job_meta.get('drive') or {}
_last_gh_step_sig = ['']

import threading as _th
_HANDOFF_EVENT = _th.Event()

def _drive_cloud_steps():
    vids_to_run = sorted([v for v in db.videos() if not bid or v.get('batch_id') == bid], key=lambda x: x.get('pos') or 0)
    for v_item in vids_to_run:
        if _HANDOFF_EVENT.is_set():
            return
        vid = v_item['id']
        for step_idx in range(8):
            if _HANDOFF_EVENT.is_set():
                return
            if step_idx == 3 and int(srv_num or 1) > 1:
                stagger_s = ((int(srv_num or 1) - 1) % 10) * 6.0
                if stagger_s > 0:
                    print(f'[AVS-CLOUD] Server #{srv_num} staggering Voice step by {stagger_s:.0f}s for smooth FameSpeak queue...', flush=True)
                    time.sleep(stagger_s)
            max_step_tries = 15 if step_idx == 3 else 8
            for attempt in range(max_step_tries):
                vf = db.video(vid) or {}
                st = str(vf.get('steps') or 'EEEEEEEE')
                if 'N' in st:
                    try:
                        db.proceed(vid)
                        st = str((db.video(vid) or {}).get('steps') or 'EEEEEEEE')
                    except Exception:
                        pass
                if step_idx < len(st) and st[step_idx] == 'D':
                    break
                db.update_video(vid, error=None, wait_until=0, paused=0)
                db.set_step(vid, step_idx, 'W')
                print(f'[AVS-CLOUD] Starting {vid} Step {step_idx+1}/8 ({STEP_NAMES[step_idx]}) (attempt {attempt+1}/{max_step_tries})...', flush=True)
                try:
                    r._run(vid, step_idx)
                except Exception as ex:
                    print(f'[AVS-CLOUD] Step {step_idx+1} exception:', ex, flush=True)
                vf_after = db.video(vid) or {}
                st_after = str(vf_after.get('steps') or 'EEEEEEEE')
                if 'N' in st_after:
                    try:
                        db.proceed(vid)
                        st_after = str((db.video(vid) or {}).get('steps') or 'EEEEEEEE')
                    except Exception:
                        pass
                if step_idx < len(st_after) and st_after[step_idx] == 'D':
                    print(f'[AVS-CLOUD] Completed {vid} Step {step_idx+1}/8 ({STEP_NAMES[step_idx]}) -> {st_after}', flush=True)
                    break
                err_msg = str(vf_after.get('error') or '')
                err_low = err_msg.lower()
                is_agy_quota = ('antigravity' in err_low) and any(k in err_low for k in ('quota', 'used up', 'ready again'))
                agy_reset_ts = 0.0
                try:
                    c_rst = sqlite3.connect(db.DB_PATH)
                    c_rst.execute("UPDATE google_accounts SET credits = 0, plan = 'Free plan' WHERE rest_until > ? OR state NOT IN ('ok', 'out')", (time.time(),))
                    rdy_cnt = (c_rst.execute("SELECT count(*) FROM google_accounts WHERE state = 'ok' AND rest_until <= ?", (time.time(),)).fetchone() or [0])[0]
                    if rdy_cnt < 4:
                        c_rst.execute("UPDATE google_accounts SET state = 'ok', rest_until = 0 WHERE state != 'out'")
                    if is_agy_quota and attempt >= 1:
                        row_rt = c_rst.execute("SELECT MIN(rest_until) FROM agy_accounts WHERE state = 'limit' AND rest_until > ?", (time.time(),)).fetchone()
                        if row_rt and row_rt[0]:
                            agy_reset_ts = float(row_rt[0])
                    if not (is_agy_quota and attempt >= 1):
                        c_rst.execute("UPDATE agy_accounts SET state = 'ok', rest_until = 0 WHERE state != 'out'")
                    c_rst.execute("UPDATE keys SET state = 'ok', note = ''")
                    c_rst.commit()
                    c_rst.close()
                except Exception:
                    pass
                if is_agy_quota and attempt >= 1:
                    import re as _re_q
                    if agy_reset_ts <= time.time():
                        m_q = _re_q.search('in\s+(\d+)\s*(h|hr|hours?|m|min|minutes?|s|sec)', err_low)
                        if m_q:
                            val_q = int(m_q.group(1))
                            unit_q = m_q.group(2)
                            sec_q = val_q * (3600 if unit_q.startswith('h') else (60 if unit_q.startswith('m') else 1))
                            agy_reset_ts = time.time() + sec_q
                    wait_sec = max(60, min(18000, int(agy_reset_ts - time.time()) + 15)) if agy_reset_ts > time.time() else 300
                    wait_min = max(1, round(wait_sec / 60))
                    print(f'[AVS-CLOUD] Antigravity quota exhausted; waiting {wait_min} min until exact reset, then auto-resuming {vid} Step {step_idx+1}/8...', flush=True)
                    db.update_video(vid, error=None, note=f'⏳ Antigravity quota used up — auto-resuming in ~{wait_min} min at exact reset...')
                    slept = 0
                    while slept < wait_sec:
                        if _HANDOFF_EVENT.is_set() or (time.time() - _JOB_START_TS) >= _HANDOFF_AGE_SEC:
                            _HANDOFF_EVENT.set()
                            return
                        chunk = min(60, wait_sec - slept)
                        time.sleep(chunk)
                        slept += chunk
                        rem_min = max(1, round((wait_sec - slept) / 60))
                        if slept < wait_sec:
                            db.update_video(vid, error=None, note=f'⏳ Antigravity quota resets in ~{rem_min} min — auto-resuming Step {step_idx+1}/8...')
                    try:
                        c_rst2 = sqlite3.connect(db.DB_PATH)
                        c_rst2.execute("UPDATE agy_accounts SET state = 'ok', rest_until = 0 WHERE state != 'out'")
                        c_rst2.commit()
                        c_rst2.close()
                    except Exception:
                        pass
                    continue
                retry_sleep = 18 if step_idx == 3 else 5
                print(f'[AVS-CLOUD] Step {step_idx+1}/8 state={st_after} err={vf_after.get("error")} note={vf_after.get("note")} -> retrying in {retry_sleep}s...', flush=True)
                time.sleep(retry_sleep)
            else:
                print(f'[AVS-CLOUD] Step {step_idx+1}/8 did not reach D after {max_step_tries} attempts; stopping remaining steps for {vid}.', flush=True)
                break

_worker_th = _th.Thread(target=_drive_cloud_steps, name='avs-cloud-step-driver', daemon=True)
_worker_th.start()

def push_status(vids_list, is_done=False):
    if not job_id:
        return
    try:
        v_docs = []
        step_only_parts = []
        for v in sorted(vids_list, key=lambda x: x.get('pos') or 0):
            v_full = db.video(v['id']) or v
            v_folder = v_full.get('folder') or ''
            steps_s = str(v_full.get('steps') or 'EEEEEEEE')
            raw_note = v_full.get('note') or ''
            err_s = v_full.get('error')
            done_marker = os.path.join(v_folder, 'drive_uploaded.json') if v_folder else ''
            drive_info = None
            if done_marker and os.path.isfile(done_marker):
                try:
                    drive_info = json.load(open(done_marker, 'r', encoding='utf-8'))
                except Exception:
                    drive_info = {'uploaded': True}
            step_i = 0
            for ch_i, ch in enumerate(steps_s):
                if ch in ('W', 'F', 'N', 'E'):
                    step_i = ch_i
                    break
            else:
                step_i = 7
            step_label = STEP_NAMES[min(step_i, 7)]
            if drive_info:
                cloud_note = f"☁️ Done! Saved in 2TB Google Drive (AI Video Studio Videos -> {drive_info.get('name', 'Video')})"
            elif len(steps_s) == 8 and all(c == 'D' for c in steps_s) and not err_s:
                cloud_note = f"☁️ [Cloud Server #{srv_num}] Uploading finished video to 2TB Google Drive..."
            elif err_s or 'F' in steps_s:
                cloud_note = f"☁️ [Cloud Server #{srv_num}] Step {step_i+1}/8 ({step_label}): {raw_note or err_s or 'Retrying...'}"
            else:
                cloud_note = f"☁️ [Cloud Server #{srv_num}] Step {step_i+1}/8 ({step_label}): {raw_note or 'Working...'}"

            thumb_b64 = ''
            files_map = {}
            if v_folder and os.path.isdir(v_folder):
                for tname in ('thumbnail.jpg', 'thumbnail-1.jpg', 'thumbnail.png'):
                    tp = os.path.join(v_folder, tname)
                    if os.path.isfile(tp) and os.path.getsize(tp) < 550 * 1024:
                        try:
                            thumb_b64 = base64.b64encode(open(tp, 'rb').read()).decode('ascii')
                            break
                        except Exception:
                            pass
                for rel_p, max_b in (
                    ('source/transcript.txt', 40000),
                    ('summary.txt', 40000),
                    ('script.txt', 60000),
                    ('captions.srt', 60000),
                    ('scenes.json', 60000),
                    ('details.txt', 40000),
                ):
                    fp = os.path.join(v_folder, *rel_p.split('/'))
                    if os.path.isfile(fp):
                        try:
                            files_map[rel_p] = open(fp, 'r', encoding='utf-8', errors='replace').read(max_b)
                        except Exception:
                            pass

            step_only_parts.append(f"{v['id']}:{steps_s}:{bool(drive_info)}")
            v_docs.append({
                'pos': v_full.get('pos') or 1,
                'title': v_full.get('title') or '',
                'new_title': v_full.get('new_title') or '',
                'channel': v_full.get('channel') or '',
                'length': v_full.get('length') or '',
                'description': v_full.get('description') or '',
                'transcript': v_full.get('transcript') or '',
                'steps': steps_s,
                'note': cloud_note,
                'error': err_s,
                'drive_uploaded': bool(drive_info),
                'drive_info': drive_info,
                'thumb_b64': thumb_b64,
                'files': files_map,
            })
        payload = {
            'job_id': job_id,
            'server_number': srv_num,
            'github_account': srv_owner,
            'updated_at': time.time(),
            'done': is_done,
            'videos': v_docs,
        }
        pushed_to_drive = False
        if status_file_id and drive_cfg.get('refresh_token'):
            try:
                drv_tok = sitecustomize._get_drive_access_token(drive_cfg)
                pushed_to_drive = sitecustomize._drive_update_json_file(drv_tok, status_file_id, payload)
            except Exception as de:
                print('[AVS-CLOUD] Drive status push warn:', de, flush=True)
        cur_step_sig = '|'.join(step_only_parts)
        if srv_token and srv_owner and (not pushed_to_drive and cur_step_sig != _last_gh_step_sig[0]):
            _last_gh_step_sig[0] = cur_step_sig
            _enc_st = sitecustomize._encrypt_cloud_job_doc(payload, os.environ.get('AVS_SECRET_KEY') or '')
            sitecustomize._github_put_file(
                srv_token, srv_owner, srv_repo,
                f'jobs/{job_id}_status.json',
                _enc_st,
                f'Status update for {job_id}',
            )
    except Exception as e:
        print('[AVS-CLOUD] Status push warn:', e, flush=True)

# 6. Monitor progress until completion & guarantee 2TB Google Drive upload
last_log = ''
last_push_sig = ''
last_push_time = 0.0

while True:
    time.sleep(4)
    vids = [v for v in db.videos() if not bid or v.get('batch_id') == bid]
    if not vids:
        if not _worker_th.is_alive():
            break
        continue

    all_finished = True
    sig_parts = []
    for v in vids:
        vid = v['id']
        v_full = db.video(vid) or v
        steps_s = str(v_full.get('steps') or 'EEEEEEEE')
        err_s = v_full.get('error')
        raw_note = v_full.get('note') or ''
        v_folder = v_full.get('folder') or ''

        done_marker = os.path.join(v_folder, 'drive_uploaded.json') if v_folder else ''
        if len(steps_s) == 8 and all(c == 'D' for c in steps_s):
            if v_folder and os.path.isfile(os.path.join(v_folder, 'video.mp4')) and not os.path.isfile(done_marker):
                push_status(vids, is_done=False)
                print(f'[AVS-CLOUD] Video {vid} finished all 8 steps! Uploading to 2TB Google Drive...', flush=True)
                up_info = sitecustomize._upload_finished_video_to_drive(v_full, clean_local=False)
                print(f'[AVS-CLOUD] Google Drive upload complete for {vid}: ok={bool(up_info)}', flush=True)
                if not up_info:
                    all_finished = False
        elif _worker_th.is_alive():
            all_finished = False

        has_up = bool(done_marker and os.path.isfile(done_marker))
        sig_parts.append(f"{vid}:{steps_s}:{has_up}")

    cur_sig = '|'.join(sig_parts)
    if cur_sig != last_log:
        print('[AVS-CLOUD] Progress:', cur_sig, flush=True)
        last_log = cur_sig

    if all_finished and not _worker_th.is_alive():
        push_status(vids, is_done=True)
        break
    if (not all_finished) and (time.time() - _JOB_START_TS) >= _HANDOFF_AGE_SEC and int(job_meta.get('handoff_count') or 0) < 6 and drive_cfg.get('refresh_token') and drive_cfg.get('folder_id'):
        if not _HANDOFF_EVENT.is_set():
            print('[AVS-CLOUD] 5h20m reached — requesting clean checkpoint handoff to fresh GitHub runner...', flush=True)
            _HANDOFF_EVENT.set()
        if not _worker_th.is_alive():
            try:
                import zipfile as _zf_ck
                push_status(vids, is_done=False)
                ck_db = os.path.join(os.getcwd(), 'ckpt_studio.db')
                _src_c = sqlite3.connect(db.DB_PATH)
                _dst_c = sqlite3.connect(ck_db)
                _src_c.backup(_dst_c)
                _dst_c.close()
                _src_c.close()
                ck_zip = os.path.join(os.getcwd(), 'checkpoint.zip')
                with _zf_ck.ZipFile(ck_zip, 'w', _zf_ck.ZIP_DEFLATED, compresslevel=1) as _cz:
                    _cz.write(ck_db, 'studio.db')
                    for _cv in vids:
                        if str(_cv.get('steps') or '') == 'DDDDDDDD':
                            continue
                        _cfd = _cv.get('folder') or ''
                        if _cfd and os.path.isdir(_cfd):
                            for _rt_d, _, _fs_l in os.walk(_cfd):
                                for _fn in _fs_l:
                                    if _fn.endswith(('.tmp', '.part')) or _fn == 'video.mp4':
                                        continue
                                    _fp = os.path.join(_rt_d, _fn)
                                    _rel = os.path.relpath(_fp, _cfd).replace(os.sep, '/')
                                    _cz.write(_fp, f"videos/{_cv['id']}/{_rel}")
                _dtok = sitecustomize._get_drive_access_token(drive_cfg)
                _up_ck = sitecustomize._drive_upload_file(_dtok, drive_cfg['folder_id'], ck_zip, 'application/zip', remote_name=f'avs_ckpt_{job_id}.zip')
                _ck_id = (_up_ck or {}).get('id') or ''
                if _ck_id:
                    with open('handoff_request.json', 'w', encoding='utf-8') as _hf:
                        json.dump({'checkpoint_file_id': _ck_id, 'handoff_count': int(job_meta.get('handoff_count') or 0) + 1}, _hf)
                    print(f'[AVS-CLOUD] Checkpoint uploaded; handing off cleanly!', flush=True)
                    break
            except Exception as _he:
                print('[AVS-CLOUD] Handoff checkpoint error:', _he, flush=True)
    elif cur_sig != last_push_sig and (time.time() - last_push_time >= 4.0):
        push_status(vids, is_done=False)
        last_push_sig = cur_sig
        last_push_time = time.time()

time.sleep(3)
print('[AVS-CLOUD] Cloud Job Completed Successfully!', flush=True)
"""
    with open(os.path.join(work, "run_cloud_batch.py"), "w", encoding="utf-8") as rf:
        rf.write(run_code)
    _delete_repo_job_file(job, job_id)
    py_exe = os.path.join(work, "python", "python.exe")
    try:
        import re as _re_log
        proc = subprocess.Popen(
            [py_exe, "run_cloud_batch.py"],
            cwd=work,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        for raw_line in proc.stdout:
            s_line = raw_line.strip()
            if not s_line.startswith("[AVS-CLOUD]"):
                continue
            s_line = _re_log.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[ACCOUNT]", s_line)
            s_line = _re_log.sub(r"(ghp_[A-Za-z0-9]+|ya29\.[A-Za-z0-9._-]+|1//[A-Za-z0-9._-]+)", "[REDACTED]", s_line)
            print(s_line, flush=True)
        rc = proc.wait()
        if rc != 0:
            raise subprocess.CalledProcessError(rc, [py_exe, "run_cloud_batch.py"])
    finally:
        _delete_repo_job_file(job, job_id)
        hf_path = os.path.join(work, "handoff_request.json")
        if os.path.isfile(hf_path):
            try:
                _trigger_handoff_job(job, json.load(open(hf_path, "r", encoding="utf-8")))
            except Exception as _hfe:
                print("[AVS-CLOUD] Handoff trigger warn:", _hfe, flush=True)
        else:
            _trigger_next_queued_job(job)

def _delete_repo_job_file(job, jid):
    owner = job.get("status_owner") or ""
    repo = job.get("status_repo") or "avs-cloud-engine"
    tok = _deobf(job.get("status_token_obf") or job.get("status_token") or "")
    if not owner or not tok or not jid:
        return
    for p_del in (f"jobs/{jid}.json", f"jobs/{jid}_status.json"):
        try:
            f_obj = _gh_api_simple(tok, "GET", f"/repos/{owner}/{repo}/contents/{p_del}")
            sha = (f_obj or {}).get("sha")
            if sha:
                _gh_api_simple(tok, "DELETE", f"/repos/{owner}/{repo}/contents/{p_del}", {"message": f"Clean {jid}", "sha": sha})
        except Exception:
            pass

def _gh_api_simple(token, method, path, data=None):
    url = path if path.startswith("http") else f"https://api.github.com{path}"
    body = json.dumps(data).encode("utf-8") if data is not None else None
    for attempt in range(4):
        req = urllib.request.Request(
            url,
            data=body,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "AIVideoStudio-Cloud",
                "X-GitHub-Api-Version": "2022-11-28",
                **({"Content-Type": "application/json"} if body is not None else {}),
            },
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=45) as resp:
                raw = resp.read().decode("utf-8", "replace")
                return json.loads(raw) if raw.strip() else {}
        except Exception as e:
            if getattr(e, "code", None) in (401, 403, 404, 422):
                raise
            if attempt < 3:
                time.sleep(2 * (attempt + 1))
                continue
            raise

def _trigger_handoff_job(job, hf_info):
    import base64
    owner = job.get("status_owner") or ""
    repo = job.get("status_repo") or "avs-cloud-engine"
    tok = _deobf(job.get("status_token_obf") or job.get("status_token") or "")
    if not owner or not tok:
        return
    h_cnt = int((hf_info or {}).get("handoff_count") or 1)
    ckpt_id = (hf_info or {}).get("checkpoint_file_id") or ""
    if not ckpt_id:
        return
    base_jid = str(job.get("job_id") or "job").split("_h")[0]
    next_jid = f"{base_jid}_h{h_cnt}"
    next_job = dict(job)
    next_job["job_id"] = next_jid
    next_job["checkpoint_file_id"] = ckpt_id
    next_job["handoff_count"] = h_cnt
    enc_bytes = _encrypt_payload_bytes(json.dumps(next_job, indent=2).encode("utf-8"))
    raw_b64 = base64.b64encode(enc_bytes).decode("ascii")
    _gh_api_simple(tok, "PUT", f"/repos/{owner}/{repo}/contents/jobs/{next_jid}.json", {
        "message": f"Handoff {next_jid}",
        "content": raw_b64,
    })
    repo_info = _gh_api_simple(tok, "GET", f"/repos/{owner}/{repo}")
    branch = (repo_info or {}).get("default_branch") or "main"
    _gh_api_simple(tok, "POST", f"/repos/{owner}/{repo}/actions/workflows/run_batch.yml/dispatches", {
        "ref": branch,
        "inputs": {"job_id": next_jid},
    })
    print(f"[AVS-CLOUD] Triggered continuation job {next_jid} on {owner}/{repo}!", flush=True)

def _trigger_next_queued_job(job):
    import base64
    owner = job.get("status_owner") or ""
    repo = job.get("status_repo") or "avs-cloud-engine"
    tok = _deobf(job.get("status_token_obf") or job.get("status_token"))
    if not owner or not tok:
        return
    try:
        items = _gh_api_simple(tok, "GET", f"/repos/{owner}/{repo}/contents/jobs/queue")
    except Exception:
        return
    if not isinstance(items, list) or not items:
        return
    q_files = sorted([x for x in items if isinstance(x, dict) and str(x.get("name") or "").endswith(".json")], key=lambda x: x["name"])
    if not q_files:
        return
    nxt_entry = q_files[0]
    nxt_path = nxt_entry.get("path") or f"jobs/queue/{nxt_entry['name']}"
    nxt_sha = nxt_entry.get("sha") or ""
    try:
        f_obj = _gh_api_simple(tok, "GET", f"/repos/{owner}/{repo}/contents/{nxt_path}")
        nxt_sha = f_obj.get("sha") or nxt_sha
        meta = json.loads(base64.b64decode(f_obj.get("content") or "").decode("utf-8", "replace"))
    except Exception as e:
        print("[AVS-CLOUD] Next queued job read warn:", e, flush=True)
        return
    nxt_job_id = meta.get("job_id") or ""
    nxt_branch = meta.get("branch") or "main"
    if not nxt_job_id:
        return
    try:
        if nxt_sha:
            _gh_api_simple(tok, "DELETE", f"/repos/{owner}/{repo}/contents/{nxt_path}", {"message": f"Dequeue {nxt_job_id}", "sha": nxt_sha})
    except Exception as e:
        print("[AVS-CLOUD] Dequeue warn:", e, flush=True)
    try:
        _gh_api_simple(tok, "POST", f"/repos/{owner}/{repo}/actions/workflows/run_batch.yml/dispatches", {"ref": nxt_branch, "inputs": {"job_id": nxt_job_id}})
        print(f"[AVS-CLOUD] Auto-chained next queued Cloud job: {nxt_job_id} on {owner}", flush=True)
    except Exception as e:
        print(f"[AVS-CLOUD] Auto-chain dispatch warn for {nxt_job_id}:", e, flush=True)

if __name__ == "__main__":
    main()
