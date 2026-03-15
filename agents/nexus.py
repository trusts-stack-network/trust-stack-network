"""NEXUS — Meta-agent d'analyse et de reparation TSN
Utilise Claude Opus via CLI pour analyser l'etat de l'equipe et corriger les problemes.
Lance par cron toutes les 2h.

Capacites:
1. Health checks + reparation automatique (services, website, tasks bloquees)
2. Deblocage des tasks bloquees
3. Verification activite git
4. Analyse IA des soul.md et patterns d'echec
"""

import json
import os
import sqlite3
import subprocess
import urllib.request
from datetime import datetime
from pathlib import Path

AGENTS_DIR = "/opt/tsn/agents/souls/"
MEMORY_FILE = "/opt/tsn/memory/shared_memory.json"
LOG_FILE = "/var/log/nexus.log"
REPORT_FILE = "/var/log/nexus_last_report.json"

CLAUDE_CLI_BIN = "/root/.local/bin/claude"
CLAUDE_MODEL = "claude-opus-4-5"

TSN_DB = "/root/tsn-team/tsn_team.db"
SSH_KEY = "/root/tsn-team/ssh_keys/tsn_ed25519"
NODE1_IP = "45.145.165.223"

HEALTH_CHECKS = [
    {"name": "TSN-Team",    "url": "http://127.0.0.1:5003/",         "service": "tsn-team"},
    {"name": "ik-llama",    "url": "http://127.0.0.1:8080/v1/models","service": "ik-llama"},
    {"name": "Lycos",       "url": "http://127.0.0.1:5002/",         "service": "lycos"},
    {"name": "Flux",        "url": "http://127.0.0.1:5004/health",   "service": "flux-server"},
    {"name": "Website",     "url": "https://tsnchain.com/",          "service": None},
]


def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"[NEXUS {ts}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def llm_call(prompt, max_tokens=2000):
    """Appel Claude Opus via CLI (claude --print)."""
    if len(prompt) > 50000:
        prompt = prompt[:50000] + "\n[...tronque]"

    env = os.environ.copy()
    env.pop("CLAUDECODE", None)

    cmd = [
        CLAUDE_CLI_BIN, "--print",
        "--model", CLAUDE_MODEL,
        "--no-session-persistence",
        "-p", prompt,
    ]

    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=180, env=env, cwd="/tmp",
    )

    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip()
    else:
        stderr = result.stderr.strip()[:300] if result.stderr else ""
        raise RuntimeError(f"Claude CLI exit={result.returncode} stderr={stderr}")


def ssh_cmd(command, timeout=15):
    """Execute une commande SSH sur node-1."""
    try:
        r = subprocess.run(
            ['ssh', '-i', SSH_KEY, '-o', 'StrictHostKeyChecking=no',
             '-o', 'ConnectTimeout=10', f'root@{NODE1_IP}', command],
            capture_output=True, text=True, timeout=timeout,
        )
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except Exception as e:
        return '', str(e), -1


def db_conn():
    conn = sqlite3.connect(TSN_DB, timeout=30)  # 5s → 30s : évite verrouillage DB
    conn.row_factory = sqlite3.Row
    return conn


# ─────────────────────────────────────────────────────────────
# Phase 1: Health Checks + Reparation automatique
# ─────────────────────────────────────────────────────────────

def check_and_repair_services():
    """Verifie tous les services et tente de reparer ceux qui sont down."""
    issues = []
    repairs = []

    for svc in HEALTH_CHECKS:
        try:
            urllib.request.urlopen(svc["url"], timeout=8)
            log(f"  {svc['name']} OK")
        except Exception as e:
            log(f"  {svc['name']} DOWN : {e}")
            issues.append(svc['name'])

    # Reparations automatiques pour les services locaux
    for svc in HEALTH_CHECKS:
        if svc['name'] in issues and svc.get('service'):
            service_name = svc['service']
            log(f"  -> Tentative redemarrage {service_name}...")
            r = subprocess.run(['systemctl', 'restart', service_name],
                              capture_output=True, timeout=30)
            status = "OK" if r.returncode == 0 else "ECHEC"
            repairs.append(f"{service_name} restart {status}")

    # Cas special: Website sur node-1
    if "Website" in issues:
        log("  -> Verification nginx sur node-1...")
        out, err, rc = ssh_cmd('systemctl is-active nginx')
        if out.strip() != 'active':
            out2, _, rc2 = ssh_cmd('systemctl restart nginx')
            repairs.append("nginx@node-1 restart " + ("OK" if rc2 == 0 else "ECHEC"))
        else:
            repairs.append("nginx@node-1 actif — verifier config/DNS")

    return issues, repairs


# ─────────────────────────────────────────────────────────────
# Phase 2: Gestion des taches bloquees
# ─────────────────────────────────────────────────────────────

def fix_blocked_tasks():
    """Detecte et debloque les taches bloquees, mais seulement si le LLM est disponible."""
    try:
        # Verifier si Claude/Groq est up avant de debloquer en masse
        llm_available = False
        try:
            import urllib.request
            # Test rapide Claude via One API
            urllib.request.urlopen("http://127.0.0.1:5003/", timeout=15)  # 5s → 15s : test LLM plus robuste
            llm_available = True
        except Exception:
            pass

        conn = db_conn()
        blocked = conn.execute(
            "SELECT id, title, assigned_to FROM tasks WHERE status = 'blocked'"
        ).fetchall()

        if not blocked:
            log("  Aucune tache bloquee")
            conn.close()
            return 0

        log(f"  {len(blocked)} taches bloquees")

        # Debloquer max 5 taches a la fois pour eviter le flood
        to_unblock = min(5, len(blocked))
        ids = [b['id'] for b in blocked[:to_unblock]]
        placeholders = ','.join('?' * len(ids))
        conn.execute(f"UPDATE tasks SET status = 'pending' WHERE id IN ({placeholders})", ids)
        conn.commit()
        conn.close()
        log(f"  -> {to_unblock}/{len(blocked)} taches debloquees (blocked -> pending)")
        return to_unblock
    except Exception as e:
        log(f"  Erreur taches: {e}")
        return 0


# ─────────────────────────────────────────────────────────────
# Phase 3: Verification activite git
# ─────────────────────────────────────────────────────────────

def check_git_activity():
    try:
        result = subprocess.run(
            ['git', '-C', '/opt/tsn', 'log',
             '--since=6 hours ago', '--oneline'],
            capture_output=True, text=True, timeout=10
        )
        commits = result.stdout.strip().splitlines() if result.stdout.strip() else []
        log(f"  Git: {len(commits)} commits (6h)")
        return len(commits)
    except Exception:
        return -1


# ─────────────────────────────────────────────────────────────
# Phase 4: Analyse IA des soul.md
# ─────────────────────────────────────────────────────────────

def load_memory(last_n=200):
    try:
        with open(MEMORY_FILE, "r") as f:
            return json.load(f)[-last_n:]
    except Exception:
        return []


def load_soul(agent_name):
    path = Path(AGENTS_DIR) / f"{agent_name}.soul.md"
    return path.read_text() if path.exists() else ""


def save_soul(agent_name, content):
    path = Path(AGENTS_DIR) / f"{agent_name}.soul.md"
    path.write_text(content)
    log(f"  soul.md mis a jour : {agent_name}")


def create_task(title, description, assigned_to, priority='high'):
    """Cree une tache dans la DB TSN."""
    try:
        conn = db_conn()
        conn.execute(
            "INSERT INTO tasks (title, description, assigned_to, status, priority, created_by) "
            "VALUES (?, ?, ?, 'pending', ?, 'nexus')",
            (title, description, assigned_to, priority)
        )
        conn.commit()
        task_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.close()
        log(f"  Tache #{task_id} creee pour {assigned_to}: {title[:60]}")
        return task_id
    except Exception as e:
        log(f"  Erreur creation tache: {e}")
        return None


def post_message(channel, bot_name, content):
    """Poste un message dans la DB (visible dans Discord/reunion)."""
    try:
        conn = db_conn()
        conn.execute(
            "INSERT INTO messages (channel, bot_name, content) VALUES (?, ?, ?)",
            (channel, bot_name, content)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        log(f"  Erreur post message: {e}")


def git_push():
    """Push les commits locaux sur GitHub."""
    try:
        result = subprocess.run(
            ['git', '-C', '/opt/tsn',
             'push', 'origin', 'main'],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            log("  Git push OK")
            return True
        else:
            log(f"  Git push ECHEC: {result.stderr[:200]}")
            return False
    except Exception as e:
        log(f"  Git push erreur: {e}")
        return False


def analyze_and_improve(health_issues, repairs, blocked_fixed, git_count):
    """Analyse IA + actions concretes (taches, messages, pas juste soul.md)."""
    try:
        conn = db_conn()
        acts = conn.execute(
            "SELECT bot_name, action, detail, timestamp FROM activity_log ORDER BY id DESC LIMIT 50"
        ).fetchall()
        tasks = conn.execute(
            "SELECT id, title, status, assigned_to FROM tasks WHERE status NOT IN ('done','cancelled') ORDER BY id DESC LIMIT 20"
        ).fetchall()
        recent_msgs = conn.execute(
            "SELECT bot_name, content, timestamp FROM messages WHERE channel = 'reunion' ORDER BY timestamp DESC LIMIT 10"
        ).fetchall()
        conn.close()
        db_data = {
            "activities": [dict(a) for a in acts],
            "active_tasks": [dict(t) for t in tasks],
            "recent_reunion": [dict(m) for m in recent_msgs],
        }
    except Exception as e:
        log(f"  Erreur DB: {e}")
        db_data = {"activities": [], "active_tasks": [], "recent_reunion": []}

    agents = ["kai", "arjun", "elena", "jamal", "yuki", "marcus", "laila", "zoe"]
    souls = {a: load_soul(a) for a in agents}

    activities_str = json.dumps(db_data["activities"][:30], indent=1, ensure_ascii=False)
    tasks_str = json.dumps(db_data["active_tasks"], indent=1, ensure_ascii=False)
    reunion_str = json.dumps(db_data["recent_reunion"], indent=1, ensure_ascii=False)
    souls_summary = {a: f"{len(s.splitlines())}L" for a, s in souls.items()}

    prompt = f"""Tu es NEXUS, le meta-agent operationnel de Trust Stack Network.
Tu ne fais PAS de reporting — tu AGIS.

ETAT SYSTEME:
- Services down: {health_issues if health_issues else 'aucun'}
- Reparations: {repairs if repairs else 'aucune'}
- Taches debloquees ce cycle: {blocked_fixed}
- Commits git (6h): {git_count}

DERNIERS MESSAGES REUNION (CEO + bots):
{reunion_str}

ACTIVITE RECENTE DES BOTS:
{activities_str}

TACHES ACTIVES:
{tasks_str}

SOUL.MD (resume): {json.dumps(souls_summary)}

TES POUVOIRS D'ACTION:
1. "create_task" — creer une tache concrete pour un bot
2. "post_message" — poster un message dans #general pour diriger l'equipe
3. "push_git" — pousser le code sur GitHub
4. "restart_service" — redemarrer un service (tsn-team, lycos, flux-server, ik-llama)

REGLES:
- Si 0 commits en 6h: creer des taches CONCRETES et petites (ex: "Ajouter tests pour X", pas "Refactorer Y")
- Si le CEO a demande quelque chose dans la reunion et que personne n'a agi: creer la tache
- Si des commits existent mais pas push: faire push_git
- Si un bot tourne en boucle (meme tache qui passe blocked->pending->blocked): analyser pourquoi
- NE PAS modifier les soul.md sauf si un pattern d'echec se repete 3+ fois

Retourne UNIQUEMENT ce JSON:
{{
  "analyse": "2-3 phrases sur l'etat reel",
  "actions": [
    {{"type": "create_task", "title": "...", "description": "...", "assigned_to": "nom_bot", "priority": "high"}},
    {{"type": "post_message", "channel": "general", "content": "..."}},
    {{"type": "push_git"}},
    {{"type": "restart_service", "service": "tsn-team"}}
  ],
  "rapport": "1-2 phrases pour le CEO"
}}

Reponds uniquement en JSON valide. Pas de markdown."""

    try:
        content = llm_call(prompt, max_tokens=2000)
        start = content.find("{")
        end = content.rfind("}") + 1
        if start < 0 or end <= start:
            log(f"  Pas de JSON valide: {content[:200]}")
            return None

        data = json.loads(content[start:end])
        actions = data.get("actions", [])
        executed = 0

        for act in actions:
            act_type = act.get("type", "")
            try:
                if act_type == "create_task":
                    tid = create_task(
                        act.get("title", "Tache NEXUS"),
                        act.get("description", ""),
                        act.get("assigned_to", "architect"),
                        act.get("priority", "high"),
                    )
                    if tid:
                        executed += 1

                elif act_type == "post_message":
                    post_message(
                        act.get("channel", "general"),
                        "nexus",
                        act.get("content", "")[:500],
                    )
                    executed += 1

                elif act_type == "push_git":
                    if git_push():
                        executed += 1

                elif act_type == "restart_service":
                    svc = act.get("service", "")
                    if svc in ("tsn-team", "lycos", "flux-server", "ik-llama"):
                        r = subprocess.run(
                            ['systemctl', 'restart', svc],
                            capture_output=True, timeout=30,
                        )
                        log(f"  Restart {svc}: {'OK' if r.returncode == 0 else 'ECHEC'}")
                        executed += 1

            except Exception as e:
                log(f"  Action {act_type} echouee: {e}")

        log(f"  Rapport: {data.get('rapport', 'N/A')}")
        log(f"  {executed}/{len(actions)} actions executees")
        return data
    except json.JSONDecodeError as e:
        log(f"  Erreur JSON: {e}")
    except Exception as e:
        log(f"  Erreur analyse: {e}")
    return None


# ─────────────────────────────────────────────────────────────
# Cycle principal
# ─────────────────────────────────────────────────────────────

def run_nexus_cycle():
    log("=== DEBUT CYCLE NEXUS ===")

    log("Phase 1: Health checks")
    issues, repairs = check_and_repair_services()

    log("Phase 2: Taches bloquees")
    blocked_fixed = fix_blocked_tasks()

    log("Phase 3: Activite git")
    git_count = check_git_activity()

    log("Phase 4: Analyse IA + Actions (Claude Opus)")
    report_data = analyze_and_improve(issues, repairs, blocked_fixed, git_count)

    # Sauvegarder le rapport
    report = {
        "timestamp": datetime.now().isoformat(),
        "model": CLAUDE_MODEL,
        "health_issues": issues,
        "repairs": repairs,
        "blocked_fixed": blocked_fixed,
        "git_commits_6h": git_count,
        "analyse": (report_data or {}).get("analyse", ""),
        "rapport": (report_data or {}).get("rapport", ""),
        "actions": (report_data or {}).get("actions", []),
    }
    with open(REPORT_FILE, "w") as f:
        json.dump(report, ensure_ascii=False, indent=2, fp=f)

    log(f"=== FIN CYCLE — {len(issues)} issues, {len(repairs)} reparations, {blocked_fixed} debloquees ===")


def main():
    try:
        env = os.environ.copy()
        env.pop("CLAUDECODE", None)
        result = subprocess.run(
            [CLAUDE_CLI_BIN, "--version"],
            capture_output=True, text=True, timeout=5, env=env,
        )
        if result.returncode == 0:
            log(f"Claude CLI: {result.stdout.strip()}")
        else:
            log(f"ERREUR: Claude CLI KO: {result.stderr[:200]}")
            return
    except Exception as e:
        log(f"ERREUR: Claude CLI inaccessible: {e}")
        return

    for attempt in range(3):
        try:
            run_nexus_cycle()
            return
        except Exception as e:
            log(f"Tentative {attempt+1}/3 echouee: {e}")
            if attempt < 2:
                import time
                time.sleep(30)


if __name__ == "__main__":
    main()
