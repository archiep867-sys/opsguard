import pytest

from opsguard.safety_engine import Decision, evaluate_command

SAFE = [
    "kubectl logs web-1 --tail=100", "kubectl top pods", "kubectl config current-context",
    "git log --oneline -5", "git diff", "git branch", "git branch -a", "git show HEAD",
    "docker ps", "docker images", "docker logs web", "helm list", "helm status web",
    "aws s3 ls", "aws ec2 describe-instances", "aws sts get-caller-identity", "aws iam list-users",
    "df -h", "uptime", "whoami", "date",
]
REVIEW = [
    "kubectl set image deployment/web web=web:v2", "kubectl exec web-1 -- /bin/sh", "kubectl cordon node1",
    "kubectl drain node1", "docker restart web", "docker stop web", "docker run -d nginx",
    "docker build -t app .", "helm upgrade web ./chart", "helm install web ./chart",
    "git commit -m fix", "git push origin main", "git pull", "git checkout feature", "git merge main",
    "git branch -D old", "aws s3 rm s3://prod-data/one-file.txt",
]
NOT_SAFE = [
    "git diff --output=/tmp/x",           # writes a file
    "date -s 2020-01-01",                 # sets the clock
    "date --set=2020-01-01",
    "hostname newname",                   # renames the host
    "aws ssm get-parameter --name p --with-decryption",  # reads a secret
    "docker ps; rm -rf /",                # shell chaining
    "docker ps | sh",
    "nmap -sV localhost",                 # unknown stays unknown
    "cat /etc/shadow",
]


@pytest.mark.parametrize("command", SAFE)
def test_read_only_commands_are_safe(command):
    assert evaluate_command(command).decision is Decision.SAFE


@pytest.mark.parametrize("command", REVIEW)
def test_state_changing_commands_need_review(command):
    assert evaluate_command(command).decision is Decision.REVIEW


@pytest.mark.parametrize("command", NOT_SAFE)
def test_traps_are_never_safe(command):
    assert evaluate_command(command).decision is not Decision.SAFE


def test_force_push_still_blocked():
    assert evaluate_command("git push --force origin main").decision is Decision.BLOCK
