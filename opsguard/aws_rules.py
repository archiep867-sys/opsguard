"""High-risk AWS command checks used by the safety engine."""

PUBLIC_ACL = {"public-read", "public-read-write", "authenticated-read"}


def aws_high_risk(lower):
    """Return a reason if an AWS command is destructive or opens broad access."""
    if len(lower) < 3:
        return None
    joined = " ".join(lower)
    if lower[1] == "s3" and lower[2] == "rb":
        return "Removing an S3 bucket is prohibited."
    if lower[1] == "s3" and lower[2] in {"rm", "mv"} and "--recursive" in lower:
        return "Recursive S3 deletion is prohibited."
    if lower[1] == "s3" and lower[2] == "sync" and "--delete" in lower:
        return "S3 sync with --delete removes objects and is prohibited."
    if "administratoraccess" in joined:
        return "Granting AdministratorAccess is prohibited."
    if any(a in PUBLIC_ACL or a.split("=", 1)[-1] in PUBLIC_ACL for a in lower[2:]):
        return "Making AWS resources publicly readable is prohibited."
    if "authorize-security-group-ingress" in lower and ("0.0.0.0/0" in joined or "::/0" in joined):
        return "Opening a security group to the whole internet is prohibited."
    return None
