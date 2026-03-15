"""Agent Recovery — Wrapper MCP retry avec reflect_on_failure.

Fournit un décorateur/wrapper pour les appels MCP des agents TSN.
- Max 3 tentatives, backoff exponentiel 2s/5s/15s
- Avant chaque retry, reflect_on_failure analyse l'erreur via LLM
- Si 3 retries échouent, escalade à Architect (Kai.V)
- Log chaque tentative
"""

import time
import logging
import json
from datetime import datetime

logger = logging.getLogger('agent-recovery')

BACKOFF_DELAYS = [2, 5, 15]
MAX_RETRIES = 3


def reflect_on_failure(llm_client, error, task_context, agent_name):
    """Demande au LLM d'analyser l'erreur et reformuler l'approche."""
    prompt = f"""Tu es un assistant de debug pour l'agent {agent_name} du projet TSN.

L'agent a rencontré cette erreur lors d'un appel MCP :
{str(error)[:500]}

Contexte de la tâche :
{str(task_context)[:500]}

Analyse l'erreur et propose :
1. La cause probable (1 ligne)
2. Une approche alternative pour le retry (1-2 lignes)
3. Si l'erreur est permanente (true/false)

Réponds en JSON : {{"cause": "...", "nouvelle_approche": "...", "permanent": false}}"""

    try:
        if hasattr(llm_client, 'generate'):
            response = llm_client.generate(
                [{'role': 'user', 'content': prompt}],
                max_tokens=200, temperature=0.1
            )
        else:
            return {'cause': str(error)[:100], 'nouvelle_approche': 'retry direct', 'permanent': False}

        if response:
            start = response.find('{')
            end = response.rfind('}') + 1
            if start >= 0 and end > start:
                return json.loads(response[start:end])
        return {'cause': str(error)[:100], 'nouvelle_approche': 'retry direct', 'permanent': False}
    except Exception:
        return {'cause': str(error)[:100], 'nouvelle_approche': 'retry direct', 'permanent': False}


def escalate_to_architect(db, agent_name, tool_name, error, task_context):
    """Crée une tâche d'escalade pour Architect."""
    if not db:
        logger.error("Pas de DB pour escalade")
        return
    title = f'[ESCALADE] {agent_name}: {tool_name} échoué 3x'
    description = (
        f'Agent: {agent_name}\n'
        f'Outil MCP: {tool_name}\n'
        f'Erreur: {str(error)[:500]}\n'
        f'Contexte: {str(task_context)[:500]}\n'
        f'Timestamp: {datetime.now().isoformat()}\n\n'
        f'Action requise: Kai.V doit analyser et décider.'
    )
    try:
        db.execute(
            'INSERT INTO tasks (title, description, status, priority, assigned_to) VALUES (?, ?, ?, ?, ?)',
            (title, description, 'assigned', 'critical', 'architect'),
            commit=True,
        )
        logger.info("Escalade créée pour architect: %s", title[:80])
    except Exception as e:
        logger.error("Erreur escalade: %s", e)


def mcp_retry(func, agent_name, tool_name, tool_input,
              llm_client=None, db=None, task_context=None):
    """Execute un appel MCP avec retry + reflect_on_failure.

    Args:
        func: La fonction à appeler (dispatch_tool ou similaire)
        agent_name: Nom de l'agent (ex: 'core')
        tool_name: Nom de l'outil MCP (ex: 'tsn_write_file')
        tool_input: Dict des paramètres
        llm_client: LLMService pour reflect_on_failure
        db: Database pour escalade
        task_context: Contexte de la tâche en cours

    Returns:
        Le résultat de func, ou None si tous les retries échouent
    """
    last_error = None

    for attempt in range(MAX_RETRIES):
        try:
            result = func(tool_name, tool_input)

            # Vérifier si le résultat contient une erreur
            if isinstance(result, str) and result.startswith('ERREUR'):
                raise RuntimeError(result)

            logger.info("[%s] %s: OK (attempt %d)", agent_name, tool_name, attempt + 1)
            return result

        except Exception as e:
            last_error = e
            logger.warning(
                "[%s] %s: FAIL attempt %d/%d — %s",
                agent_name, tool_name, attempt + 1, MAX_RETRIES, str(e)[:200]
            )

            if attempt < MAX_RETRIES - 1:
                # Reflect on failure avant le retry
                if llm_client:
                    reflection = reflect_on_failure(llm_client, e, task_context, agent_name)
                    logger.info("[%s] Reflection: %s", agent_name, json.dumps(reflection, ensure_ascii=False)[:200])

                    if reflection.get('permanent', False):
                        logger.warning("[%s] Erreur permanente détectée, skip retries", agent_name)
                        break

                # Backoff exponentiel
                delay = BACKOFF_DELAYS[attempt]
                logger.info("[%s] Backoff %ds avant retry", agent_name, delay)
                time.sleep(delay)

    # Tous les retries échoués — escalade
    logger.error("[%s] %s: ÉCHEC après %d tentatives", agent_name, tool_name, MAX_RETRIES)
    escalate_to_architect(db, agent_name, tool_name, last_error, task_context)
    return None
