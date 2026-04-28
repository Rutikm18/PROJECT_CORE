import sys
# Prepend our source directory so our code takes priority over any
# host-installed packages with the same name.  DO NOT replace sys.path
# entirely — that kills stdlib (argparse, os, etc.) and site-packages.
sys.path.insert(0, '/Library/AttackLens/src')
from agent.agent_entry import main
main()
