import os, json, re, hashlib, time, requests, feedparser

TG_TOKEN = os.environ["TG_TOKEN"]
TG_CHAT = os.environ["TG_CHAT"]
GROQ_KEY = os.environ.get("GROQ_KEY")  # opcional
STATE = "state.json"
UA = {"User-Agent": "Mozilla/5.0 (alert-bot personal)"}

# =====================================================================
# CONFIGURACION: EDITA SOLO ESTA SECCION
# =====================================================================

# 1) Tecnologias / fabricantes que te importan (vulnerabilidades).
#    Una alerta de vulnerabilidad solo llega si menciona alguna de estas.
#    Escribe palabras en minuscula separadas por "|".
TECH = (
    "fortigate|fortios|fortinet|fortiems|forticlient|forticlient ems|"
    "linux|linux kernel|php|"
    "lotix"
)

# 2) Si es True, TODO lo que entre al catalogo CISA KEV te llega aunque no
#    este en TECH (son las explotadas activamente). Ponelo en False para
#    filtrar tambien KEV por TECH.
KEV_TODO = False

# 3) Empresas / marcas del sector que te importan (incidentes).
#    Solo se alerta si el TITULO menciona una de estas Y una palabra de incidente.
SECTOR = (
    "casino|igaming|i-gaming|gambling|sportsbook|betting|bet365|apuestas|"
    "loter[ií]a|lottery|lotto|bookmaker|stake\\.com|gamdom|duelbits|"
    "lotix|playtech|evolution gaming|igt|scientific games|light & wonder|"
    "sportradar|tragamonedas|juego online|kambi|pragmatic play|novomatic"
)

# 4) Palabras de incidente
INCIDENT = (
    "breach|hack|ransomware|leak|stolen|drain|ddos|extortion|"
    "filtraci[oó]n|ciberataque|intrusi[oó]n|compromis|cyberattack|cyber attack"
)

# 5) Si el titulo contiene esto, se DESCARTA (para cortar ruido).
EXCLUIR = (
    "review|bonus|promo|best casino|top \\d+|how to win|odds|picks|"
    "predictions|giveaway|welcome offer|stock|shares|earnings"
)

# 6) Palabras que marcan una vulnerabilidad grave en una noticia
VULN = (
    "zero[- ]?day|0[- ]?day|actively exploited|exploited in the wild|"
    "critical vulnerability|cvss (9|10)|remote code execution|rce|"
    "pre-auth|explotad[ao] activamente|d[ií]a cero|emergency patch"
)

RSS = [
    "https://www.bleepingcomputer.com/feed/",
    "https://therecord.media/feed/",
    "https://www.securityweek.com/feed/",
    "https://feeds.feedburner.com/TheHackersNews",
    "https://cvefeed.io/rssfeed/severity/high.xml",
    # Agrega aqui RSS de medios de iGaming / loteria
]
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
RLIVE = "https://api.ransomware.live/v2/recentvictims"

# =====================================================================
# FIN DE LA CONFIGURACION
# =====================================================================

R_TECH = re.compile(rf"\b({TECH})\b", re.I)
R_SECTOR = re.compile(rf"\b({SECTOR})\b", re.I)
R_INCIDENT = re.compile(rf"({INCIDENT})", re.I)
R_EXCLUIR = re.compile(rf"\b({EXCLUIR})\b", re.I)
R_VULN = re.compile(rf"\b({VULN})\b", re.I)


def load():
    try:
        return json.load(open(STATE))
    except Exception:
        return {"seen": [], "kev": []}


def h(s):
    return hashlib.sha256(s.encode()).hexdigest()[:16]


def tg(text):
    r = requests.post(
        f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
        data={"chat_id": TG_CHAT, "text": text[:4000], "disable_web_page_preview": True},
        timeout=20)
    if r.status_code == 429:
        time.sleep(r.json().get("parameters", {}).get("retry_after", 5))
        tg(text)
    time.sleep(1.1)


def llm_ok(title, summary):
    if not GROQ_KEY:
        return True
    try:
        r = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {GROQ_KEY}"},
            json={"model": "llama-3.3-70b-versatile", "temperature": 0,
                  "messages": [{"role": "user", "content":
                      "¿Esta noticia trata de un ciberataque o brecha CONFIRMADA a una empresa de "
                      "loteria, casino, apuestas o iGaming? Responde solo SI o NO.\n\n"
                      f"{title}\n{summary[:800]}"}]},
            timeout=30)
        return "SI" in r.json()["choices"][0]["message"]["content"].upper()
    except Exception:
        return True  # ante la duda, alertar


def main():
    st = load()
    seen = set(st["seen"])
    out = []

    # 1) Noticias RSS
    for url in RSS:
        try:
            f = feedparser.parse(requests.get(url, headers=UA, timeout=20).content)
        except Exception:
            continue
        for e in f.entries[:40]:
            key = h(e.get("link", e.get("title", "")))
            if key in seen:
                continue
            seen.add(key)
            title = e.get("title", "")
            body = f"{title} {e.get('summary', '')}"

            # Sector: solo el TITULO, con palabra de incidente, sin ruido
            if R_SECTOR.search(title) and R_INCIDENT.search(title) and not R_EXCLUIR.search(title):
                if llm_ok(title, body):
                    out.append(f"🎰 SECTOR | {title}\n{e.get('link', '')}")
                continue

            # Vulnerabilidades: deben mencionar una tecnologia tuya
            es_cve_feed = "cvefeed.io" in url
            if (es_cve_feed or R_VULN.search(body)) and R_TECH.search(body):
                out.append(f"🛑 VULN | {title}\n{e.get('link', '')}")

    # 2) CISA KEV
    try:
        kev = requests.get(KEV, headers=UA, timeout=30).json()["vulnerabilities"]
        old = set(st["kev"])
        if old:  # primera corrida: solo guarda snapshot
            for v in kev:
                if v["cveID"] in old:
                    continue
                datos = f"{v['vendorProject']} {v['product']} {v['vulnerabilityName']}"
                if KEV_TODO or R_TECH.search(datos):
                    out.append(
                        f"🔥 KEV (explotado) {v['cveID']} – {v['vendorProject']} "
                        f"{v['product']}: {v['vulnerabilityName']}\n"
                        f"Ransomware: {v.get('knownRansomwareCampaignUse')}")
        st["kev"] = [v["cveID"] for v in kev]
    except Exception:
        pass

    # 3) ransomware.live: solo nombre y dominio de la victima
    try:
        for v in requests.get(RLIVE, headers=UA, timeout=30).json()[:100]:
            name = f"{v.get('victim', '')} {v.get('domain', '')}"
            key = h("rl" + v.get("victim", "") + v.get("group", ""))
            if key in seen:
                continue
            seen.add(key)
            if R_SECTOR.search(name):
                out.append(
                    f"💀 RANSOM (reclamo no verificado) {v.get('victim')} "
                    f"– grupo {v.get('group')} – {v.get('country')}")
    except Exception:
        pass

    for msg in out[:15]:
        tg(msg)
    if len(out) > 15:
        tg(f"(+{len(out) - 15} alertas más omitidas en esta corrida)")
    st["seen"] = list(seen)[-5000:]
    json.dump(st, open(STATE, "w"))


if __name__ == "__main__":
    main()
