import pytest

from opsguard.safety_engine import Decision, evaluate_command

CASES = [
    ("pwd", Decision.SAFE),
    ("kubectl get pods", Decision.SAFE),
    ("kubectl apply -f x.yaml", Decision.REVIEW),
    ("rm -rf /", Decision.BLOCK),
    ("dd if=/dev/zero of=/dev/sda", Decision.BLOCK),
    ("git push --force origin main", Decision.BLOCK),
    ("git reset --hard HEAD~1", Decision.BLOCK),
    ("docker system prune -af", Decision.BLOCK),
    ("helm uninstall web", Decision.BLOCK),
    ("shutdown -h now", Decision.BLOCK),
    ("nmap -sV localhost", Decision.BLOCK),
]


@pytest.mark.parametrize("command,expected", CASES)
def test_evaluation_set(command, expected):
    assert evaluate_command(command).decision is expected
