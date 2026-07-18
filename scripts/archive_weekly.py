# -*- coding: utf-8 -*-
"""
每週自動封存腳本（GitHub Actions 排程執行）

工作內容：
1. 瑪法達：抓最近一個週二的 12 篇星座週報（鏡週刊），加密封存
2. 唐綺陽：抓 Podcast RSS 新的星座運勢週報，加密封存
3. 唐綺陽：檢查 YouTube 頻道 RSS 是否有新的月運勢直播，登記「待轉錄」
4. 更新 docs/data/sealed/index.json（僅中繼資料，不含內容）

加密：AES-GCM，金鑰由環境變數 SEAL_KEY（GitHub Secret）經 PBKDF2 導出。
前端開箱時輸入同一密碼才能解密——盲測的「盲」由此保證。
"""
import base64
import datetime as dt
import json
import os
import re
import sys
from pathlib import Path

import feedparser
import requests
from bs4 import BeautifulSoup
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ROOT = Path(__file__).resolve().parents[1]
SEALED_DIR = ROOT / "docs" / "data" / "sealed"
INDEX_PATH = SEALED_DIR / "index.json"

HEADERS = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/126.0 Safari/537.36"}
ZODIAC = [("ARI", "牡羊"), ("TAU", "金牛"), ("GEM", "雙子"), ("CAN", "巨蟹"),
          ("LEO", "獅子"), ("VIR", "處女"), ("LIB", "天秤"), ("SCO", "天蠍"),
          ("SAG", "射手"), ("CAP", "魔羯"), ("AQU", "水瓶"), ("PIS", "雙魚")]
TANG_ITUNES = "https://itunes.apple.com/lookup?id=1536374746"
TANG_YT_HANDLE = "https://www.youtube.com/@jessetang1113"
PBKDF2_ITERS = 200_000


# ---------- 加密 ----------

def seal(plaintext: str, passphrase: str) -> dict:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=PBKDF2_ITERS)
    key = kdf.derive(passphrase.encode("utf-8"))
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return {
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ct": base64.b64encode(ct).decode(),
        "kdf_iters": PBKDF2_ITERS,
    }


# ---------- 索引 ----------

def load_index() -> dict:
    if INDEX_PATH.exists():
        return json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    return {"updated_at": "", "items": [], "pending_transcripts": []}


def save_index(index: dict) -> None:
    index["updated_at"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    INDEX_PATH.parent.mkdir(parents=True, exist_ok=True)
    INDEX_PATH.write_text(json.dumps(index, ensure_ascii=False, indent=1), encoding="utf-8")


def index_has(index: dict, item_id: str) -> bool:
    return any(it["id"] == item_id for it in index["items"])


def write_sealed_item(index: dict, item_id: str, meta: dict, plaintext: str, passphrase: str) -> None:
    month = meta["period_start"][:7]
    rel_path = f"{month}/{item_id}.json"
    out_path = SEALED_DIR / rel_path
    out_path.parent.mkdir(parents=True, exist_ok=True)
    record = {**meta, "id": item_id, "sealed": seal(plaintext, passphrase),
              "archived_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")}
    out_path.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
    index["items"].append({"id": item_id, "path": rel_path, "month": month,
                           **{k: meta[k] for k in ("author", "cycle", "zodiac", "period_start", "period_end")}})
    print(f"  ✓ 封存 {item_id}")


# ---------- 瑪法達 ----------

def most_recent_tuesday(today: dt.date) -> dt.date:
    return today - dt.timedelta(days=(today.weekday() - 1) % 7)


def fetch_mafalda(index: dict, passphrase: str) -> None:
    print("【瑪法達】")
    tue = most_recent_tuesday(dt.date.today())
    session = requests.Session()
    for i, (code, name) in enumerate(ZODIAC, start=1):
        item_id = f"MFD-W-{tue:%Y%m%d}-{code}"
        if index_has(index, item_id):
            continue
        html = None
        for offset in (0, -1, 1):
            d = tue + dt.timedelta(days=offset)
            url = f"https://www.mirrormedia.mg/story/{d:%Y%m%d}maf{i:03d}"
            try:
                resp = session.get(url, headers=HEADERS, timeout=20)
            except requests.RequestException:
                continue
            if resp.status_code == 200:
                html = resp.text
                break
        if not html:
            print(f"  ✗ 未找到：{name}（可能尚未發布）")
            continue
        soup = BeautifulSoup(html, "html.parser")
        def meta_tag(prop):
            tag = soup.find("meta", property=prop)
            return tag["content"].strip() if tag and tag.get("content") else ""
        title = meta_tag("og:title")
        sign_para = meta_tag("og:description")
        published = meta_tag("article:published_time")[:10]
        m = re.search(r"(\d{2})\.(\d{2})\s*[~～]\s*(\d{2})\.(\d{2})", title)
        if m and published:
            y = int(published[:4])
            sm, sd, em, ed = map(int, m.groups())
            ey = y + 1 if em < sm else y
            ps, pe = f"{y:04d}-{sm:02d}-{sd:02d}", f"{ey:04d}-{em:02d}-{ed:02d}"
        else:
            ps = pe = str(tue)
        if not sign_para:
            print(f"  ✗ 解析失敗：{name}")
            continue
        write_sealed_item(index, item_id, {
            "author": "mafalda", "cycle": "weekly", "zodiac": code,
            "period_start": ps, "period_end": pe, "title": title,
        }, sign_para, passphrase)


# ---------- 唐綺陽週報 ----------

def fetch_tang_weekly(index: dict, passphrase: str) -> None:
    print("【唐綺陽週報】")
    resp = requests.get(TANG_ITUNES, headers=HEADERS, timeout=20)
    feed_url = resp.json()["results"][0]["feedUrl"]
    feed = feedparser.parse(requests.get(feed_url, headers=HEADERS, timeout=30).content)
    cutoff = dt.date.today() - dt.timedelta(days=21)
    for entry in feed.entries[:12]:
        pub = dt.date(*entry.published_parsed[:3]) if entry.get("published_parsed") else None
        if not pub or pub < cutoff:
            continue
        raw = entry.get("summary", "") or ""
        if entry.get("content"):
            raw = max([raw] + [c.get("value", "") for c in entry.content], key=len)
        raw = re.sub(r"<[^>]+>", "\n", raw)
        m = re.search(r"【唐綺陽\s*(\d{1,2})/(\d{1,2})\s*[-–]\s*(\d{1,2})/(\d{1,2})\s*星座運勢週報】", raw)
        if not m:
            continue
        sm, sd, em, ed = map(int, m.groups())
        sy = pub.year - 1 if (sm == 12 and pub.month == 1) else (pub.year + 1 if (sm == 1 and pub.month == 12) else pub.year)
        ey = sy + 1 if em < sm else sy
        ps = dt.date(sy, sm, sd)
        item_id = f"TANG-W-{ps:%Y%m%d}-ALL"
        if index_has(index, item_id):
            continue
        write_sealed_item(index, item_id, {
            "author": "tang", "cycle": "weekly", "zodiac": "ALL",
            "period_start": ps.isoformat(), "period_end": dt.date(ey, em, ed).isoformat(),
            "title": entry.get("title", ""),
        }, raw.strip(), passphrase)


# ---------- 唐綺陽月運直播（僅偵測，不抓內容） ----------

def check_tang_youtube(index: dict) -> None:
    print("【唐綺陽月運直播偵測】")
    try:
        page = requests.get(TANG_YT_HANDLE, headers=HEADERS, timeout=20).text
        m = re.search(r'"channelId":"(UC[^"]+)"', page)
        if not m:
            print("  ⚠ 無法解析 channelId，跳過")
            return
        rss = requests.get(f"https://www.youtube.com/feeds/videos.xml?channel_id={m.group(1)}",
                           headers=HEADERS, timeout=20)
        feed = feedparser.parse(rss.content)
    except requests.RequestException as e:
        print(f"  ⚠ 連線失敗：{e}")
        return
    known = {p["video_id"] for p in index["pending_transcripts"]}
    for entry in feed.entries:
        title = entry.get("title", "")
        if "月運勢" not in title:
            continue
        vid = entry.get("yt_videoid", "")
        if not vid or vid in known:
            continue
        index["pending_transcripts"].append({
            "video_id": vid, "title": title,
            "url": f"https://www.youtube.com/watch?v={vid}",
            "published": entry.get("published", "")[:10],
            "status": "待轉錄",
        })
        print(f"  ★ 偵測到新月運直播：{title}")


def main():
    passphrase = os.environ.get("SEAL_KEY", "")
    if not passphrase:
        sys.exit("錯誤：環境變數 SEAL_KEY 未設定。請在 GitHub repo Settings → Secrets → Actions 新增 SEAL_KEY。")
    index = load_index()
    n_before = len(index["items"])
    fetch_mafalda(index, passphrase)
    try:
        fetch_tang_weekly(index, passphrase)
    except Exception as e:
        print(f"  ⚠ 唐綺陽週報抓取失敗：{e}")
    check_tang_youtube(index)
    save_index(index)
    print(f"\n完成：本次新增 {len(index['items']) - n_before} 筆封存，索引已更新")


if __name__ == "__main__":
    main()
