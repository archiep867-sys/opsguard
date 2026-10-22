import pytest

from opsguard.safety_engine import Decision, evaluate_command

BLOCKED = [
    "aws s3 rb s3://prod-data --force",
    "aws s3 rm s3://prod-data --recursive",
    "aws s3 mv s3://prod-data s3://other --recursive",
    "aws s3 sync ./empty s3://prod-data --delete",
    "aws iam attach-user-policy --user-name ci-bot --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
    "aws s3api put-bucket-acl --bucket reports --acl public-read",
    "aws ec2 authorize-security-group-ingress --group-id sg-1 --protocol tcp --port 22 --cidr 0.0.0.0/0",
    "aws ec2 authorize-security-group-ingress --group-id sg-1 --protocol tcp --port 22 --cidr=0.0.0.0/0",
]


@pytest.mark.parametrize("command", BLOCKED)
def test_high_risk_aws_commands_are_blocked(command):
    assert evaluate_command(command).decision is Decision.BLOCK


@pytest.mark.parametrize("command", [
    "aws s3 rm s3://prod-data/one-file.txt",
    "aws s3api put-bucket-acl --bucket reports --acl private",
    "aws ec2 authorize-security-group-ingress --group-id sg-1 --protocol tcp --port 22 --cidr 10.0.0.0/8",
    "aws ec2 describe-instances",
])
def test_ordinary_aws_commands_keep_review(command):
    assert evaluate_command(command).decision is Decision.REVIEW
