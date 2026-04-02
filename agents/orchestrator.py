"""TSN Orchestrator — Build monitor (passive).

DISABLED: Ce service est desactivé. Le pre-commit hook cargo check
empêche désormais les commits qui cassent le build.
ARCHITECT et NEXUS gèrent la réparation si nécessaire.

L'ancien orchestrateur créait des dizaines de tâches "Build casse"
en boucle car Qwen3.5 local ne pouvait pas réparer du Rust complexe.
"""

import sys
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [ORCHESTRATOR] %(message)s'
)
logger = logging.getLogger('orchestrator')


def main():
    logger.info("Orchestrator DISABLED — pre-commit hook handles build validation")
    logger.info("Use ARCHITECT or NEXUS for build repair")
    sys.exit(0)


if __name__ == '__main__':
    main()
