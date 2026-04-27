import sys
# Hard-reset sys.path to our installed source only.
# Must run before any other import — prevents host-env package conflicts.
sys.path = ['/Library/AttackLens/src']
from agent.agent_entry import main
main()
