import os, json, re, hashlib, time, requests, feedparser

TG_TOKEN = os.environ["TG_TOKEN"]; TG_CHAT = os.environ["TG_CHAT"]
GROQ_KEY = os.environ.get("GROQ_KEY")  # opcional
STATE = "state.json"
UA = {"User-Agent": "Mozilla/5.0 (alert-bot personal)"}

RSS = [
 "https://www.bleepingcomputer.com/feed/",
 "https://therecord.media/feed/",
 "https://www.securityweek.com/feed/",
 "https://feeds.feedburner.com/TheHackersNews",
 "https://cvefeed.io/rssfeed/severity/high.xml",
 # + RSS de medios iGaming/lotería y, opcional, RSS de una instancia Nitter
]
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
RLIVE = "https://api.ransomware.live/v2/recentvictims"

SECTOR = re.compile(r"\b(casino|igaming|i-gaming|gambling|sportsbook|betting|bet365|apuestas?|"
                    r"loter[ií]a|lottery|lotto|slots?|bookmaker|poker|stake\.com|gamdom|duelbits|"
                    r"playtech|evolution gaming|igt|scientific games|light & wonder|sportradar|"
                    r"tragamonedas|juego online)\b", re.I)
INCIDENT = re.compile(r"\b(breach|hack(ed|eo)?|ransomware|leak(ed)?|data breach|stolen|drain(ed)?|"
                      r"ddos|extortion|filtraci[oó]n|ciberataque|intrusi[oó]n|compromis)\w*", re.I)
VULN = re.compile(r"\b(zero[- ]?day|0[- ]?day|actively exploited|exploited in the wild|"
                  r"critical vulnerability|cvss\s*(9|10)|rce|remote code execution|"
                  r"explotad[ao] activamente|d[ií]a cero)\b", re.I)

def load():
    try: return json.load(open(STATE))
    except Exception: return {"seen": [], "kev": []}

def h(s): return hashlib.sha256(s.encode()).hexdigest()[:16]

def tg(text):
    r = requests.post(f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
        data={"chat_id": TG_CHAT, "text": text[:4000], "disable_web_page_preview": True}, timeout=20)
    if r.status_code == 429:
        time.sleep(r.json().get("parameters", {}).get("retry_after", 5)); tg(text)
    time.sleep(1.1)

def llm_ok(title, summary):
    if not GROQ_KEY: return True
    try:
        r = requests.post("https://api.groq.com/openai/v1/chat/completions",
          headers={"Authorization": f"Bearer {GROQ_KEY}"},
          json={"model": "llama-3.3-70b-versatile", "temperature": 0,
                "messages": [{"role": "user", "content":
                 "¿Esta noticia trata de un ciberataque/brecha a una empresa de lotería, casino, "
                 "apuestas o iGaming, o de una vulnerabilidad crítica/zero-day explotada? "
                 f"Responde solo SI o NO.\n\n{title}\n{summary[:800]}"}]}, timeout=30)
        return "SI" in r.json()["choices"][0]["message"]["content"].upper()
    except Exception:
        return True  # ante la duda, alertar

def main():
    st = load(); seen = set(st["seen"]); out = []
    # 1) Noticias RSS
    for url in RSS:
        try: f = feedparser.parse(requests.get(url, headers=UA, timeout=20).content)
        except Exception: continue
        for e in f.entries[:40]:
            key = h(e.get("link", e.get("title", "")))
            if key in seen: continue
            seen.add(key)
            txt = f"{e.get('title','')} {e.get('summary','')}"
            sector = SECTOR.search(txt) and INCIDENT.search(txt)
            vuln = VULN.search(txt) or "cvefeed.io" in url
            if (sector or vuln) and (not sector or llm_ok(e.get("title",""), txt)):
                tag = "🎰 SECTOR" if sector else "🛑 VULN"
                out.append(f"{tag} | {e.get('title','')}\n{e.get('link','')}")
    # 2) CISA KEV: nuevos CVE explotados
    try:
        kev = requests.get(KEV, headers=UA, timeout=30).json()["vulnerabilities"]
        old = set(st["kev"])
        if old:  # primera corrida: solo guarda snapshot
            for v in kev:
                if v["cveID"] not in old:
                    out.append(f"🔥 KEV (explotado) {v['cveID']} – {v['vendorProject']} "
                               f"{v['product']}: {v['vulnerabilityName']}\n"
                               f"Ransomware: {v.get('knownRansomwareCampaignUse')}")
        st["kev"] = [v["cveID"] for v in kev]
    except Exception: pass
    # 3) ransomware.live: víctimas del sector
    try:
        for v in requests.get(RLIVE, headers=UA, timeout=30).json()[:100]:
            name = f"{v.get('victim','')} {v.get('domain','')} {v.get('description','')}"
            key = h("rl" + v.get("victim", "") + v.get("group", ""))
            if key in seen: continue
            seen.add(key)
            if SECTOR.search(name):
                out.append(f"💀 RANSOM (reclamo no verificado) {v.get('victim')} "
                           f"– grupo {v.get('group')} – {v.get('country')}")
    except Exception: pass
    for msg in out[:15]: tg(msg)
    if len(out) > 15: tg(f"(+{len(out)-15} alertas más omitidas en esta corrida)")
    st["seen"] = list(seen)[-5000:]
    json.dump(st, open(STATE, "w"))

if __name__ == "__main__": main()
