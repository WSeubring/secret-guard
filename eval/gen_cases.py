#!/usr/bin/env python3
"""Generate the labelled evaluation set as JSONL on stdout.

Fake credentials are built at runtime from a fixed seed, so no secret-looking
literal lives in this repository. Each case: {id, label, kind, family, event}.
label is "secret" (must block) or "clean" (must pass).
"""
import base64
import json
import os
import random
import re
import string
import struct
import sys
from urllib.parse import quote

R = random.Random(int(sys.argv[1]) if len(sys.argv) > 1 else 1337)
A62 = string.ascii_letters + string.digits
HEXL = "0123456789abcdef"
B64 = A62 + "+/"
URLSAFE = A62 + "-_"


def rnd(n, alphabet=A62):
    return "".join(R.choice(alphabet) for _ in range(n))


def b64url(obj):
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")


def jwt(payload=None):
    header = {"alg": R.choice(["HS256", "RS256", "ES256"]), "typ": "JWT"}
    payload = payload or {"sub": rnd(12), "iat": R.randint(1_600_000_000, 1_800_000_000), "exp": R.randint(1_800_000_000, 1_900_000_000)}
    return f"{b64url(header)}.{b64url(payload)}.{rnd(43, URLSAFE)}"


def pem_body(lines=25):
    return "\n".join(rnd(64, B64) for _ in range(lines)) + "\n" + rnd(R.randint(10, 60), B64) + "=="


def password():
    kind = R.randrange(5)
    if kind == 0:
        return rnd(R.randint(16, 32))
    if kind == 1:
        pool = A62 + "!#%^*+=?~"
        while True:
            p = rnd(R.randint(12, 24), pool)
            if any(c.isdigit() for c in p) and any(c.islower() for c in p) and any(c.isupper() for c in p):
                return p
    if kind == 2:
        word = R.choice(["Zomer", "Winter", "Haven", "Fiets", "Tulip", "Kanaal", "Molen", "Spring", "Orange"])
        return f"{word}{R.randint(2000, 2029)}{R.choice('!#?')}"
    if kind == 3:
        return rnd(R.randint(20, 40), "abcdefghijklmnopqrstuvwxyz0123456789")
    return rnd(R.choice([32, 40, 64]), HEXL)


# --------------------------------------------------------------------------- provider tokens

TOKENS = {
    "aws-access-key-id": lambda: R.choice(["AKIA", "ASIA"]) + rnd(16, string.ascii_uppercase + "234567"),
    "github-token": lambda: R.choice(["ghp_", "gho_", "ghu_", "ghs_", "ghr_"]) + rnd(36),
    "github-fine-grained-pat": lambda: f"github_pat_{rnd(22)}_{rnd(59)}",
    "gitlab-token": lambda: R.choice(["glpat-", "gldt-", "glrt-", "glptt-", "gloas-"]) + rnd(20, URLSAFE),
    "gitlab-token-routable": lambda: "glpat-" + rnd(27, URLSAFE) + ".01." + rnd(9, "abcdefghijklmnopqrstuvwxyz0123456789"),
    "gitlab-runner-registration": lambda: "GR1348941" + rnd(20, URLSAFE),
    "slack-token": lambda: f"xox{R.choice('bp')}-{R.randint(10**11, 10**12)}-{R.randint(10**12, 10**13)}-{rnd(24)}",
    "slack-app-token": lambda: f"xapp-1-A{rnd(10, string.ascii_uppercase + string.digits)}-{R.randint(10**12, 10**13)}-{rnd(64, HEXL)}",
    "slack-webhook": lambda: f"https://hooks.slack.com/services/T{rnd(10, string.ascii_uppercase + string.digits)}/B{rnd(10, string.ascii_uppercase + string.digits)}/{rnd(24)}",
    "stripe-live-key": lambda: R.choice(["sk_live_", "rk_live_"]) + rnd(R.choice([24, 99])),
    "stripe-webhook-secret": lambda: "whsec_" + rnd(32),
    "openai-key": lambda: "sk-proj-" + rnd(R.choice([48, 156]), URLSAFE),
    "openai-legacy-key": lambda: "sk-" + rnd(20) + "T3BlbkFJ" + rnd(20),
    "anthropic-key": lambda: "sk-ant-api03-" + rnd(93, URLSAFE) + "AA",
    "google-api-key": lambda: "AIza" + rnd(35, URLSAFE),
    "google-oauth-client-secret": lambda: "GOCSPX-" + rnd(28, URLSAFE),
    "google-oauth-refresh-token": lambda: "1//0" + rnd(R.randint(60, 100), URLSAFE),
    "google-oauth-access-token": lambda: "ya29." + rnd(R.randint(120, 200), URLSAFE),
    "digitalocean-token": lambda: R.choice(["dop_v1_", "doo_v1_"]) + rnd(64, HEXL),
    "docker-hub-token": lambda: "dckr_pat_" + rnd(27, URLSAFE),
    "npm-token": lambda: "npm_" + rnd(36),
    "pypi-token": lambda: "pypi-AgEIcHlwaS5vcmc" + rnd(R.randint(60, 150), URLSAFE),
    "huggingface-token": lambda: "hf_" + rnd(34, string.ascii_letters),
    "sendgrid-key": lambda: f"SG.{rnd(22, URLSAFE)}.{rnd(43, URLSAFE)}",
    "shopify-token": lambda: R.choice(["shpat_", "shpss_"]) + rnd(32, HEXL),
    "atlassian-token": lambda: "ATATT3" + rnd(186, URLSAFE + "="),
    "azure-ad-client-secret": lambda: rnd(3) + str(R.randint(0, 9)) + "Q~" + rnd(34, A62 + "_~.-"),
    "azure-storage-key": lambda: f"DefaultEndpointsProtocol=https;AccountName=st{rnd(8, 'abcdefghijklmnopqrstuvwxyz')};AccountKey={rnd(86, B64)}==;EndpointSuffix=core.windows.net",
    "tailscale-key": lambda: f"tskey-auth-{rnd(12)}-{rnd(32)}",
    "grafana-service-account-token": lambda: f"glsa_{rnd(32)}_{rnd(8, HEXL)}",
    "grafana-cloud-token": lambda: "glc_" + rnd(R.randint(60, 120)) + "==",
    "1password-service-account": lambda: "ops_eyJ" + rnd(R.randint(200, 400), URLSAFE),
    "telegram-bot-token": lambda: f"{R.randint(10**8, 10**10 - 1)}:AA{rnd(33, URLSAFE)}",
    "vault-token": lambda: "hvs." + rnd(R.randint(90, 120), URLSAFE),
    "terraform-cloud-token": lambda: f"{rnd(14)}.atlasv1.{rnd(67, URLSAFE)}",
    "age-secret-key": lambda: "AGE-SECRET-KEY-1" + rnd(58, "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L"),
    "linear-key": lambda: "lin_api_" + rnd(40),
    "notion-token": lambda: "ntn_" + rnd(46),
    "sentry-token": lambda: "sntryu_" + rnd(64, HEXL),
    "databricks-token": lambda: "dapi" + rnd(32, HEXL),
    "heroku-token": lambda: "HRKU-" + rnd(60, URLSAFE),
    "postman-key": lambda: f"PMAK-{rnd(24, HEXL)}-{rnd(34, HEXL)}",
    "groq-key": lambda: "gsk_" + rnd(52),
    "xai-key": lambda: "xai-" + rnd(80),
    "perplexity-key": lambda: "pplx-" + rnd(48),
    "replicate-token": lambda: "r8_" + rnd(37),
    "plane-api-key": lambda: "plane_api_" + rnd(32, HEXL),
    "doppler-token": lambda: "dp.st." + rnd(44),
    "mailchimp-key": lambda: rnd(32, HEXL) + f"-us{R.randint(1, 21)}",
    "mailgun-key": lambda: "key-" + rnd(32, HEXL),
    "akamai-client-token": lambda: f"akab-{rnd(16, string.ascii_lowercase + string.digits)}-{rnd(16, string.ascii_lowercase + string.digits)}",
    "alibaba-access-key-id": lambda: "LTAI" + rnd(R.choice([12, 16, 20])),
    "posthog-personal-key": lambda: "phx_" + rnd(43),
    "wundergraph-key": lambda: "cosmo_" + rnd(32, HEXL),
    "grafana-api-key": lambda: b64(json.dumps({"k": rnd(32), "n": "ci", "id": R.randint(1, 99)}, separators=(",", ":"))),
    "nkey-seed": lambda: "S" + R.choice("ANOU") + rnd(56, string.ascii_uppercase + "234567"),
    "paseto-token": lambda: f"v{R.randint(1, 4)}.{R.choice(['local', 'public'])}.{rnd(R.randint(100, 200), URLSAFE)}",
    "paserk-key": lambda: f"k{R.randint(1, 4)}.{R.choice(['local', 'secret'])}.{rnd(R.choice([43, 86, 150]), URLSAFE)}",
    "jwk-private-key": lambda: json.dumps({"kty": "EC", "crv": "P-256", "x": rnd(43, URLSAFE), "y": rnd(43, URLSAFE), "d": rnd(43, URLSAFE)}, separators=(",", ":")),
    "jwt": jwt,
    "discord-webhook": lambda: f"https://discord.com/api/webhooks/{R.randint(10**17, 10**18)}/{rnd(68, URLSAFE)}",
}

# Where a token can show up. {t} is the token.
TOKEN_CONTEXTS = [
    ("prompt", "here is the token: {t}"),
    ("prompt", "can you check why {t} gets a 401?"),
    ("prompt", "use {t}"),
    ("prompt", "{t}"),
    ("prompt", "I rotated it, new value is {t} please update the sealed secret"),
    ("bash", "export API_TOKEN={t}"),
    ("bash", "curl -s -H \"Authorization: Bearer {t}\" https://api.example.org/v1/me"),
    ("bash", "curl -H 'PRIVATE-TOKEN: {t}' https://gitlab.com/api/v4/projects"),
    ("bash", "echo '{t}' | kubectl create secret generic app --from-file=token=/dev/stdin --dry-run=client -o yaml"),
    ("bash", "op item edit app credential={t}"),
    ("write", "API_TOKEN={t}\nLOG_LEVEL=info\n"),
    ("write", "auth:\n  token: \"{t}\"\n  url: https://api.example.org\n"),
    ("write", "{{\n  \"name\": \"svc\",\n  \"credentials\": \"{t}\"\n}}\n"),
    ("write", "client = Client(api_key=\"{t}\", timeout=30)\n"),
    ("write", "const cfg = {{ key: '{t}', region: 'eu' }};\n"),
    ("edit", "TOKEN = \"{t}\""),
    ("mcp", "New credential for the bot: {t}"),
]

PASSWORD_CONTEXTS = [
    ("prompt", "my password is {p}"),
    ("prompt", "het wachtwoord is {p}"),
    ("prompt", "the db password: {p}"),
    ("prompt", "login with admin / password = {p}"),
    ("bash", "psql postgres://app:{p}@db.prod.internal:5432/app -c 'select 1'"),
    ("bash", "mysql -u root -p'{p}' -h 10.0.0.5 app"),
    ("bash", "mysqldump -uroot -p{p} app > dump.sql"),
    ("bash", "curl -u admin:{p} https://registry.example.org/v2/_catalog"),
    ("bash", "docker login -u bot --password '{p}' registry.example.org"),
    ("bash", "export DB_PASSWORD='{p}'"),
    ("bash", "sshpass -p '{p}' ssh root@10.0.0.7"),
    ("bash", "app --db-password={p} --port 8080"),
    ("write", "DB_PASSWORD={p}\nDB_HOST=db.prod.internal\n"),
    ("write", "database:\n  host: db.prod.internal\n  password: \"{p}\"\n"),
    ("write", "spring.datasource.password={p}\n"),
    ("write", "{{\"user\": \"svc\", \"password\": \"{p}\"}}\n"),
    ("write", "DATABASE_URL=postgresql://svc:{p}@pg-rw.prod.svc:5432/svc\n"),
    ("write", "REDIS_URL=rediss://default:{p}@redis.example.org:6380/0\n"),
    ("write", "mongo = MongoClient(\"mongodb+srv://svc:{p}@cluster0.abcde.mongodb.net/app\")\n"),
    ("write", "apiVersion: v1\nkind: Secret\nmetadata:\n  name: db\nstringData:\n  password: {p}\n"),
    ("write", "smtp_password = \"{p}\"\n"),
    ("edit", "SECRET_KEY_BASE = \"{p}\""),
    ("mcp", "the password is {p} for the staging admin"),
]


def b64(s):
    return base64.b64encode(s.encode()).decode()


def b64(text):
    return base64.b64encode(text.encode()).decode()


SPECIAL_POSITIVES = [
    ("base64-neutral-key", lambda: f"data:\n  config: {b64(TOKENS['github-token']())}\n"),
    ("base64-dockerconfig", lambda: ".dockerconfigjson: " + b64(json.dumps({"auths": {"registry.gitlab.com": {"auth": b64("deploy:" + TOKENS["gitlab-token"]())}}}))),
    ("base64-env-file", lambda: "ENV_FILE: " + b64(f"APP_ENV=prod\nSLACK_TOKEN={TOKENS['slack-token']()}\n")),
    ("base64-decode-cmd", lambda: f"echo {b64(TOKENS['anthropic-key']())} | base64 -d > ~/.key"),
    ("private-key", lambda: f"-----BEGIN {R.choice(['RSA ', 'EC ', 'OPENSSH ', ''])}PRIVATE KEY-----\n{pem_body()}\n-----END PRIVATE KEY-----\n"),
    ("private-key-json", lambda: json.dumps({"type": "service_account", "project_id": "proj-" + rnd(6, 'abcdefghijklmnopqrstuvwxyz'), "private_key_id": rnd(40, HEXL), "private_key": f"-----BEGIN PRIVATE KEY-----\n{pem_body()}\n-----END PRIVATE KEY-----\n", "client_email": "sa@proj.iam.gserviceaccount.com"}, indent=2)),
    ("k8s-secret-data", lambda: f"apiVersion: v1\nkind: Secret\nmetadata:\n  name: app\ndata:\n  password: {b64(password())}\n"),
    ("basic-auth", lambda: f"curl -H 'Authorization: Basic {b64('svc:' + password())}' https://api.example.org"),
    ("kubeconfig-client-key", lambda: f"users:\n- name: admin\n  user:\n    client-key-data: {b64('-----BEGIN RSA PRIVATE KEY-----' + chr(10) + pem_body(10) + chr(10) + '-----END RSA PRIVATE KEY-----')}\n"),
    ("aws-secret-key", lambda: f"[default]\naws_access_key_id = AKIA{rnd(16, string.ascii_uppercase + '234567')}\naws_secret_access_key = {rnd(40, B64)}\n"),
    ("azure-sas", lambda: f"https://st{rnd(6, 'abcdefghijklmnopqrstuvwxyz')}.blob.core.windows.net/c/f.csv?sv=2022-11-02&ss=b&srt=o&sp=r&se=2027-01-01T00:00:00Z&sig={rnd(44, A62)}%3D"),
    ("git-remote-token", lambda: f"git remote set-url origin https://oauth2:{password()}@gitlab.example.org/group/repo.git"),
]


# --------------------------------------------------------------------------- clean cases

def sealed_blob():
    return "Ag" + rnd(R.randint(600, 800), B64) + "=="


def sha(n=64):
    return rnd(n, HEXL)


FIXTURE_FILLERS = {
    "hex40": lambda: sha(40),
    "hex64": lambda: sha(),
    "urlsafe20": lambda: rnd(20, URLSAFE),
    "port": lambda: str(R.randint(7000, 7999)),
    "lower26": lambda: rnd(26, string.ascii_lowercase + string.digits),
}


def regression_fixtures():
    """False positives seen in real repos and transcripts; shared with tests/regressions.rs."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests", "fixtures", "clean-regressions.jsonl")
    with open(path) as f:
        templates = [json.loads(line) for line in f if line.strip()]
    fill = lambda t: re.sub(r"\{(hex40|hex64|urlsafe20|port|lower26)\}", lambda m: FIXTURE_FILLERS[m.group(1)](), t)
    return [lambda t=t: fill(t) for t in templates]


def uuid():
    h = rnd(32, HEXL)
    return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-a{h[17:20]}-{h[20:]}"


CLEAN = [
    # placeholders for provider formats
    ("placeholder", lambda: "export GITLAB_TOKEN=glpat-xxxxxxxxxxxxxxxxxxxx"),
    ("placeholder", lambda: "data:\n  config: " + b64("GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n")),
    ("prose", lambda: "msg: " + b64("the password lives in the vault, ask the on-call engineer")),
    ("placeholder", lambda: "GITHUB_TOKEN=ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"),
    ("placeholder", lambda: "ANTHROPIC_API_KEY=sk-ant-api03-..."),
    ("placeholder", lambda: "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("placeholder", lambda: "SLACK_BOT_TOKEN=xoxb-your-bot-token-here"),
    ("placeholder", lambda: "mg = Mailgun('key-3ax6xnjp29jd6fds4gc373sgvjxteol0')"),
    ("placeholder", lambda: "STRIPE_KEY=sk_live_YOUR_SECRET_KEY_HERE"),
    ("placeholder", lambda: "api_key: <your-api-key>"),
    ("placeholder", lambda: "password: \"********\""),
    ("placeholder", lambda: "token: [REDACTED]"),
    ("placeholder", lambda: "DB_PASSWORD=changeme"),
    ("placeholder", lambda: "OPENAI_API_KEY=sk-proj-your-key-here"),
    ("placeholder", lambda: "password: 'password123'"),
    ("placeholder", lambda: "export TOKEN=your_token_here"),
    ("placeholder", lambda: "DATABASE_URL=postgres://user:password@localhost:5432/db"),
    ("placeholder", lambda: "DATABASE_URL=postgres://postgres:postgres@localhost:5432/app_dev"),
    ("placeholder", lambda: "amqp://guest:guest@localhost:5672/"),
    ("placeholder", lambda: "mongodb+srv://<username>:<password>@cluster0.mongodb.net/"),
    ("placeholder", lambda: "the jwt.io example eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
    ("placeholder", lambda: "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"),
    ("placeholder", lambda: "-----BEGIN PRIVATE KEY-----\nMIIE...your key here...\n-----END PRIVATE KEY-----"),
    ("placeholder", lambda: "token: 0000000000000000000000000000000000000000"),
    ("placeholder", lambda: "secret = \"abcdefghijklmnopqrstuvwxyz123456\""),
    # references / templates
    ("reference", lambda: "export GITLAB_TOKEN=\"$(cat ~/.config/glab-token)\""),
    ("reference", lambda: "curl -H \"PRIVATE-TOKEN: $GITLAB_TOKEN\" https://gitlab.com/api/v4/user"),
    ("reference", lambda: "curl -H \"Authorization: Bearer ${TOKEN}\" https://api.example.org"),
    ("reference", lambda: "token: ${{ secrets.GITHUB_TOKEN }}"),
    ("reference", lambda: "password: {{ .Values.postgresql.auth.password | quote }}"),
    ("reference", lambda: "password: \"{{ db_password }}\""),
    ("reference", lambda: "api_key = os.environ[\"API_KEY\"]"),
    ("reference", lambda: "api_key = os.getenv(\"API_KEY\")"),
    ("reference", lambda: "const apiKey = process.env.OPENAI_API_KEY;"),
    ("reference", lambda: "password: <%= ENV['DB_PASSWORD'] %>"),
    ("reference", lambda: "password: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  " + rnd(64, HEXL)),
    ("reference", lambda: "password: ENC[AES256_GCM,data:" + rnd(24, B64) + ",iv:" + rnd(44, B64) + "=,tag:" + rnd(22, B64) + "==,type:str]"),
    ("reference", lambda: "password: op://Vault/postgres/password"),
    ("reference", lambda: "client_secret = settings.OAUTH_CLIENT_SECRET"),
    ("reference", lambda: "token = request.headers.get(\"Authorization\")"),
    ("reference", lambda: "password = request.form[\"password\"]"),
    ("reference", lambda: "redis://:${REDIS_PASSWORD}@redis:6379/0"),
    ("reference", lambda: "git clone https://oauth2:${CI_JOB_TOKEN}@gitlab.com/group/repo.git"),
    ("reference", lambda: "secret: arn:aws:secretsmanager:eu-west-1:123456789012:secret:prod/db-AbCdEf"),
    ("reference", lambda: "export DB_PASSWORD=\"$(op read op://Infra/db/password)\""),
    ("reference", lambda: "token=\"$(kubectl get secret app -o jsonpath='{.data.token}' | base64 -d | sha256sum)\""),
    # kubernetes / helm / sealed secrets
    ("k8s", lambda: f"apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nmetadata:\n  name: app\n  namespace: prod\nspec:\n  encryptedData:\n    password: {sealed_blob()}\n    token: {sealed_blob()}\n"),
    ("k8s", lambda: f"metadata:\n  annotations:\n    checksum/secret: {sha()}\n    checksum/config: {sha()}\n"),
    ("k8s", lambda: "env:\n- name: DB_PASSWORD\n  valueFrom:\n    secretKeyRef:\n      name: db-credentials\n      key: password\n"),
    ("k8s", lambda: "auth:\n  existingSecret: airflow-gitsync-creds\n  existingSecretPasswordKey: password\n"),
    ("k8s", lambda: "tls:\n- hosts: [app.example.org]\n  secretName: app-tls-2026\n"),
    ("k8s", lambda: "serviceAccountToken:\n  path: token\n  expirationSeconds: 3600\n"),
    ("k8s", lambda: f"metadata:\n  uid: {uuid()}\n  resourceVersion: \"{R.randint(10**6, 10**8)}\"\n"),
    ("k8s", lambda: f"clusters:\n- cluster:\n    certificate-authority-data: {b64('-----BEGIN CERTIFICATE-----' + chr(10) + pem_body(8) + chr(10) + '-----END CERTIFICATE-----')}\n    server: https://10.0.0.1:6443\n"),
    ("k8s", lambda: "kubectl create secret generic db --from-file=password=./pw.txt --dry-run=client -o yaml | kubeseal --format yaml > sealed.yaml"),
    ("k8s", lambda: "kubectl get secret airflow-gitsync-creds -n airflow -o jsonpath='{.data}' | jq 'keys'"),
    ("k8s", lambda: "passwordFile: /run/secrets/db-password"),
    ("k8s", lambda: f"helm upgrade app ./chart --set image.tag=sha-{sha(7)} --set secret.name=app-creds"),
    ("k8s", lambda: "auth:\n  secretRef: app-db-v2-credentials\n"),
    ("k8s", lambda: "secret: release-v2-creds"),
    ("k8s", lambda: "existingSecret: prod-db-2026-credentials"),
    # hashes, ids, digests
    ("hash", lambda: f"git checkout {sha(40)}"),
    ("hash", lambda: f"commit {sha(40)}\nAuthor: Dev <dev@example.org>\n"),
    ("hash", lambda: f"image: ghcr.io/org/app@sha256:{sha()}"),
    ("hash", lambda: f"\"integrity\": \"sha512-{rnd(86, B64)}==\""),
    ("hash", lambda: f"[[package]]\nname = \"serde\"\nchecksum = \"{sha()}\"\n"),
    ("hash", lambda: f"github.com/foo/bar v1.2.3 h1:{rnd(43, B64)}="),
    ("hash", lambda: f"password_hash = \"$2b$12${rnd(53, A62 + './')}\""),
    ("hash", lambda: f"request_id: {uuid()}"),
    ("hash", lambda: f"trace_id={sha(32)} span_id={sha(16)}"),
    ("hash", lambda: f"etag: \"{sha(32)}\""),
    ("hash", lambda: f"sha256sum: {sha()}  release.tar.gz"),
    ("hash", lambda: f"<link href=\"/assets/main.{sha(8)}.css\" integrity=\"sha384-{rnd(64, B64)}\">"),
    ("hash", lambda: f"docker run --rm {sha(12)} sh"),
    ("hash", lambda: f"\"id\": \"{rnd(24)}\""),
    ("hash", lambda: f"fingerprint: {':'.join(sha(2) for _ in range(16))}"),
    ("hash", lambda: f"{{\"nextPageToken\": \"{rnd(40, URLSAFE)}\"}}"),
    ("hash", lambda: f"\"session_id\": \"{rnd(32)}\""),
    ("hash", lambda: f"version: {R.randint(1, 9)}.{R.randint(0, 40)}.{R.randint(0, 99)}"),
    # public material
    ("public", lambda: f"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI{rnd(43, B64)} dev@laptop"),
    ("public", lambda: f"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ{rnd(300, B64)} deploy@ci"),
    ("public", lambda: f"-----BEGIN PUBLIC KEY-----\n{pem_body(6)}\n-----END PUBLIC KEY-----"),
    ("public", lambda: f"-----BEGIN CERTIFICATE-----\n{pem_body(20)}\n-----END CERTIFICATE-----"),
    ("public", lambda: f"<img src=\"data:image/png;base64,{rnd(400, B64)}=\">"),
    ("public", lambda: "SUPABASE_ANON_KEY=" + jwt({"iss": "supabase", "ref": rnd(20, 'abcdefghijklmnopqrstuvwxyz'), "role": "anon", "iat": 1700000000, "exp": 2000000000})),
    ("public", lambda: "jwt header only: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"),
    ("public", lambda: f"\"publishableKey\": \"pk_live_{rnd(24)}\""),
    ("public", lambda: json.dumps({"keys": [{"kty": "RSA", "kid": rnd(43, URLSAFE), "use": "sig", "e": "AQAB", "n": rnd(342, URLSAFE)}, {"kty": "EC", "crv": "P-256", "x": rnd(43, URLSAFE), "y": rnd(43, URLSAFE)}]}, indent=2)),
    ("public", lambda: f"paserk: k{R.randint(1, 4)}.public.{rnd(43, URLSAFE)}\nid: k4.lid.{rnd(44, URLSAFE)}"),
    ("public", lambda: f"sealed: k4.seal.{rnd(100, URLSAFE)}\nwrapped: k4.secret-pw.{rnd(120, URLSAFE)}"),
    ("public", lambda: f"nats: U{rnd(55, string.ascii_uppercase + '234567')}"),
    ("hash", lambda: f"restore cache node-modules-cache-key-{sha(32)}"),
    # code handling secrets
    ("code", lambda: "def login(username: str, password: str) -> Token:\n    return auth.verify(username, password)\n"),
    ("code", lambda: "interface Credentials {\n  password: string;\n  token?: string | null;\n}\n"),
    ("code", lambda: "const schema = z.object({ password: z.string().min(12), token: z.string().uuid() });"),
    ("code", lambda: "if token is None:\n    raise AuthError(\"missing token\")"),
    ("code", lambda: "PASSWORD_MIN_LENGTH = 12\nTOKEN_TTL_SECONDS = 3600\n"),
    ("code", lambda: "password = generate_password(length=24)\ntoken = secrets.token_urlsafe(32)\n"),
    ("code", lambda: "self.api_key = api_key\nself.token = token\n"),
    ("code", lambda: "token = jwt.encode(payload, settings.SECRET_KEY, algorithm=\"HS256\")"),
    ("code", lambda: "user.password = BCrypt::Password.create(params[:password])"),
    ("code", lambda: "pattern = re.compile(r\"ghp_[A-Za-z0-9]{36}\")"),
    ("code", lambda: "[[rules]]\nid = \"gitlab-pat\"\nregex = '''glpat-[0-9a-zA-Z_\\-]{20}'''\n"),
    ("code", lambda: "max_tokens: 4096\ntemperature: 0.2\n"),
    ("code", lambda: "\"input_tokens\": 1532, \"output_tokens\": 812"),
    ("code", lambda: "token_url: https://oauth2.googleapis.com/token\nauth_uri: https://accounts.google.com/o/oauth2/auth\n"),
    ("code", lambda: "assert password == \"\""),
    ("code", lambda: "secret = Secret(name=\"db\", namespace=ns)"),
    ("code", lambda: "echo \"$TOKEN\" | docker login registry.gitlab.com -u bot --password-stdin"),
    ("code", lambda: "gh auth login --with-token < ~/.config/gh/token"),
    ("code", lambda: "glab auth login --hostname gitlab.com --token-file ~/.config/glab-token"),
    ("code", lambda: "mysql -u root -p app"),
    ("code", lambda: "kubeseal --cert pub.pem --format yaml < secret.yaml > sealed-secret.yaml"),
    ("code", lambda: "pwd=$(pwd)\ncd \"$pwd/build\""),
    ("code", lambda: "auth: true\ntoken_type: bearer\n"),
    ("code", lambda: "password: z.string()"),
    ("code", lambda: "api_key = config.openai.api_key"),
    ("code", lambda: "TOKEN=$(gcloud auth print-access-token)"),
    ("code", lambda: f"cache_key = \"user:{R.randint(1, 10**6)}:profile\""),
    # prose
    ("prose", lambda: "the token is expired, can you rotate it?"),
    ("prose", lambda: "password is required for the staging login"),
    ("prose", lambda: "my password is too short according to the policy"),
    ("prose", lambda: "the secret is stored in 1Password under Vault/postgres"),
    ("prose", lambda: "het wachtwoord is verlopen, kun je het resetten?"),
    ("prose", lambda: "the api key is in ~/.config/hass-token, use that"),
    ("prose", lambda: "rotate the GitLab PAT for acme-bot before 2030-01-01"),
    ("prose", lambda: "why does the password reset flow send two emails?"),
    ("prose", lambda: "token: see the sealed secret in the composer repo"),
    ("prose", lambda: f"fix the bug in commit {sha(40)} that leaks tokens in logs"),
    ("prose", lambda: "use the acme-bot token from ~/.config/glab-token to approve MR !123"),
    ("prose", lambda: "the secret is that we never cached it in the first place"),
    ("prose", lambda: "Make a global claude code hook that blocks secrets in toolcalls and user input."),
    ("prose", lambda: "password was rotated on 2026-09-29 by the incident runbook"),
    # urls
    ("url", lambda: "git clone git@gitlab.com:acme/general/app.git"),
    ("url", lambda: "ssh://git@gitlab.com:22/group/repo.git"),
    ("url", lambda: "https://user@bitbucket.org/team/repo.git"),
    ("url", lambda: f"https://accounts.google.com/o/oauth2/auth?client_id={R.randint(10**11, 10**12)}-{rnd(32, 'abcdefghijklmnopqrstuvwxyz0123456789')}.apps.googleusercontent.com&state={rnd(30)}"),
    ("url", lambda: f"https://gitlab.com/acme/app/-/merge_requests/{R.randint(1, 3000)}"),
    ("url", lambda: f"https://www.youtube.com/watch?v={rnd(11, URLSAFE)}"),
    ("url", lambda: f"postgres://app@db.internal:5432/app?sslmode=require"),
    ("url", lambda: f"https://st{rnd(6, 'abcdefghijklmnopqrstuvwxyz')}.blob.core.windows.net/c/f.csv"),
    # regressions: false positives seen in real repos and transcripts
    *[("regression", fixture) for fixture in regression_fixtures()],
    # misc noise that is high entropy but not a secret
    ("noise", lambda: rnd(2000, B64)),
    ("noise", lambda: "\n".join(f"{sha(40)} refs/heads/feature-{i}" for i in range(20))),
    ("noise", lambda: f"var a=\"{rnd(60)}\",b=function(e){{return e.{rnd(8, string.ascii_letters)}}};"),
    ("noise", lambda: f"key: {rnd(20, string.ascii_lowercase)}"),
    ("noise", lambda: f"\"state\": \"{rnd(40)}\""),
    ("noise", lambda: f"aws ecr get-login-password --region eu-west-1 | docker login --username AWS --password-stdin 123456789012.dkr.ecr.eu-west-1.amazonaws.com"),
    ("noise", lambda: f"nonce: {rnd(32)}"),
    ("noise", lambda: f"csrf_token: {rnd(43, URLSAFE)}"),
]


# --------------------------------------------------------------------------- context rules

LOWER = string.ascii_lowercase
LOWDIG = LOWER + string.digits


def rbytes(n):
    return bytes(R.randrange(256) for _ in range(n))


def opaque(url=False):
    shapes = [lambda: rnd(R.randint(32, 48), URLSAFE), lambda: sha(R.choice([40, 64]))]
    return R.choice(shapes + ([] if url else [lambda: base64.b64encode(rbytes(32)).decode()]))()


def pem(kind=None):
    kind = R.choice(["RSA ", "EC ", "OPENSSH ", "", "ENCRYPTED "]) if kind is None else kind
    return f"-----BEGIN {kind}PRIVATE KEY-----\n{pem_body()}\n-----END {kind}PRIVATE KEY-----"


def claims():
    now = R.randint(1_750_000_000, 1_800_000_000)
    return R.choice([
        {"sub": uuid(), "iss": "https://auth.example.org/", "aud": "api", "scope": "read write", "iat": now, "exp": now + 3600},
        {"iss": "kubernetes/serviceaccount", "kubernetes.io/serviceaccount/namespace": "prod", "sub": "system:serviceaccount:prod:deployer"},
        {"user_id": R.randint(1, 10**6), "email": "dev@example.org", "role": "admin", "exp": now + 86400},
        {"iss": "https://gitlab.example.org", "project_path": "group/app", "ref": "main", "exp": now + 300},
    ])


def ntlm(msg_type=3, nt_len=24):
    lm, off = 24, 72
    head = b"NTLMSSP\0" + struct.pack("<I", msg_type) + struct.pack("<HHI", lm, lm, off) + struct.pack("<HHI", nt_len, nt_len, off + lm)
    return base64.b64encode(head + rbytes(40) + rbytes(lm + nt_len + 20)).decode()


def sas(sig=None):
    sig = sig or quote(base64.b64encode(rbytes(32)).decode(), safe="")
    return f"sv=2022-11-02&ss=b&srt=sco&sp=rwdl&se=2027-0{R.randint(1, 9)}-01T00:00:00Z&st=2026-01-01T00:00:00Z&spr=https&sig={sig}"


def acct():
    return "st" + rnd(R.randint(6, 12), LOWDIG)


def storage_key():
    return base64.b64encode(rbytes(64)).decode()


def basic(user, pw):
    return b64(f"{user}:{pw}")


# rule id -> (secret cases, hard-negative clean cases), each a list of (kind, generator)
RULE_FAMILIES = {
    "jwt": (
        [("write", lambda: f"ACCESS_TOKEN={jwt(claims())}\nAPI_URL=https://api.example.org\n"),
         ("bash", lambda: f"curl -s https://api.example.org/v2/orders -H \"Authorization: Bearer {jwt(claims())}\""),
         ("write", lambda: json.dumps({"access_token": jwt(claims()), "token_type": "Bearer", "expires_in": 3600}, indent=2)),
         ("prompt", lambda: f"decode this for me, I think the aud claim is wrong: {jwt(claims())}"),
         ("write", lambda: f"users:\n- name: deployer\n  user:\n    token: {jwt(claims())}\n"),
         ("edit", lambda: f"const token = \"{jwt(claims())}\";"),
         ("bash", lambda: f"export ID_TOKEN={jwt(claims())} && ./deploy.sh"),
         ("write", lambda: f"GET https://api.example.org/me\nCookie: session={jwt(claims())}; Path=/; HttpOnly\n"),
         ("mcp", lambda: f"service token for the integration: {jwt(claims())}"),
         ("prompt", lambda: f"the api returns 403 with {jwt(claims())} since this morning"),
         ("write", lambda: f"## Testing against staging\n\nUse this token:\n\n    {jwt(claims())}\n"),
         ("bash", lambda: f"websocat 'wss://ws.example.org/feed?token={jwt(claims())}'")],
        [("prompt", lambda: "the jwt.io example eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c decodes fine"),
         ("write", lambda: "NEXT_PUBLIC_SUPABASE_ANON_KEY=" + jwt({"iss": "supabase", "ref": rnd(20, LOWER), "role": "anon", "iat": 1700000000, "exp": 2000000000}) + "\n"),
         ("bash", lambda: "curl -H \"Authorization: Bearer ${ACCESS_TOKEN}\" https://api.example.org/me"),
         ("write", lambda: f"token: {b64url({'alg': 'RS256', 'typ': 'JWT'})}.{b64url(claims())}.<signature>\n"),
         ("edit", lambda: f"TEST_JWT = \"{b64url({'alg': 'HS256', 'typ': 'JWT'})}.{b64url(claims())}.fake-signature-for-unit-tests\""),
         ("mcp", lambda: f"401 on token {b64url({'alg': 'RS256', 'typ': 'JWT'})}.eyJ... (truncated in the log)"),
         ("prompt", lambda: "a JWT has the shape xxxxx.yyyyy.zzzzz; header, payload, signature"),
         ("edit", lambda: "claims = jwt.decode(token, key=jwks, algorithms=[\"RS256\"], audience=\"api\")"),
         ("write", lambda: f"unsigned: {b64url({'alg': 'none'})}.{b64url(claims())}.\n"),
         ("write", lambda: f"\"token\": \"{b64url({'alg': 'HS256'})}.{b64url(claims())}.{'x' * 43}\""),
         ("bash", lambda: "TOKEN=$(gcloud auth print-identity-token) && curl -H \"Authorization: Bearer $TOKEN\" https://run.example.app"),
         ("mcp", lambda: "the token: [REDACTED JWT], see the incident doc")]),
    "private-key": (
        [("write", lambda: pem("OPENSSH ") + "\n"),
         ("bash", lambda: f"cat > ~/.ssh/deploy_key <<'EOF'\n{pem()}\nEOF\nchmod 600 ~/.ssh/deploy_key"),
         ("write", lambda: "apiVersion: v1\nkind: Secret\nmetadata:\n  name: tls\nstringData:\n  tls.key: |\n    " + pem("RSA ").replace("\n", "\n    ") + "\n"),
         ("write", lambda: f"PRIVATE_KEY=\"{pem('').replace(chr(10), chr(92) + 'n')}\"\n"),
         ("prompt", lambda: f"here is the deploy key, add it to the CI variables:\n{pem()}"),
         ("write", lambda: f"resource \"tls_private_key\" \"x\" {{}}\nlocals {{\n  key = <<EOT\n{pem('EC ')}\nEOT\n}}\n"),
         ("write", lambda: f"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,{sha(32).upper()}\n\n{pem_body()}\n-----END RSA PRIVATE KEY-----\n"),
         ("write", lambda: f"-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n{pem_body()}\n={rnd(4, B64)}\n-----END PGP PRIVATE KEY BLOCK-----\n"),
         ("mcp", lambda: f"key for the bastion:\n```\n{pem('OPENSSH ')}\n```"),
         ("bash", lambda: f"echo \"{pem('OPENSSH ')}\" | ssh-add -"),
         ("edit", lambda: f"SIGNING_KEY = \"\"\"{pem('')}\"\"\""),
         ("write", lambda: json.dumps({"app_id": R.randint(10**5, 10**6), "private_key": pem("RSA ") + "\n"}))],
        [("prompt", lambda: "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"),
         ("write", lambda: "tls.key: |\n  -----BEGIN PRIVATE KEY-----\n  <your private key here>\n  -----END PRIVATE KEY-----\n"),
         ("edit", lambda: "if first_line.startswith(\"-----BEGIN OPENSSH PRIVATE KEY-----\"):\n    kind = \"openssh\""),
         ("edit", lambda: "PEM_RE = re.compile(r\"-----BEGIN (RSA |EC )?PRIVATE KEY-----.*?-----END\", re.S)"),
         ("bash", lambda: "grep -rl 'BEGIN RSA PRIVATE KEY' --include='*.pem' ."),
         ("write", lambda: "-----BEGIN PRIVATE KEY-----\n[REDACTED]\n-----END PRIVATE KEY-----\n"),
         ("write", lambda: "-----BEGIN PRIVATE KEY-----\n{{ .Values.tls.key | indent 2 }}\n-----END PRIVATE KEY-----\n"),
         ("write", lambda: f"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\n"),
         ("write", lambda: f"-----BEGIN CERTIFICATE-----\n{pem_body(20)}\n-----END CERTIFICATE-----\n"),
         ("mcp", lambda: "the key file starts with -----BEGIN OPENSSH PRIVATE KEY----- and ends with the matching END line"),
         ("write", lambda: "-----BEGIN PRIVATE KEY-----\n" + "\n".join("A" * 64 for _ in range(8)) + "\n-----END PRIVATE KEY-----\n"),
         ("bash", lambda: "openssl genpkey -algorithm ed25519 -out key.pem && openssl pkey -in key.pem -pubout")]),
    "aws-secret-key": (
        [("write", lambda: f"AWS_ACCESS_KEY_ID={TOKENS['aws-access-key-id']()}\nAWS_SECRET_ACCESS_KEY={rnd(40, B64)}\nAWS_REGION=eu-west-1\n"),
         ("bash", lambda: f"export AWS_SECRET_ACCESS_KEY={rnd(40, B64)}"),
         ("bash", lambda: f"docker run --rm -e AWS_ACCESS_KEY_ID={TOKENS['aws-access-key-id']()} -e AWS_SECRET_ACCESS_KEY={rnd(40, B64)} amazon/aws-cli s3 ls"),
         ("write", lambda: f"- uses: aws-actions/configure-aws-credentials@v4\n  with:\n    aws-access-key-id: {TOKENS['aws-access-key-id']()}\n    aws-secret-access-key: {rnd(40, B64)}\n"),
         ("write", lambda: json.dumps({"AWS_ACCESS_KEY_ID": TOKENS["aws-access-key-id"](), "AWS_SECRET_ACCESS_KEY": rnd(40, B64)}, indent=2)),
         ("edit", lambda: f"s3 = boto3.client(\"s3\", aws_access_key_id=\"{TOKENS['aws-access-key-id']()}\", aws_secret_access_key=\"{rnd(40, B64)}\")"),
         ("write", lambda: f"provider \"aws\" {{\n  region     = \"eu-west-1\"\n  access_key = \"{TOKENS['aws-access-key-id']()}\"\n  secret_key = \"{rnd(40, B64)}\"\n}}\naws_secret_key = \"{rnd(40, B64)}\"\n"),
         ("prompt", lambda: f"aws secret key: {rnd(40, B64)}"),
         ("mcp", lambda: f"new creds for the backup user, aws_secret_access_key={rnd(40, B64)}"),
         ("write", lambda: f"apiVersion: v1\nkind: Secret\nmetadata:\n  name: s3\nstringData:\n  AWS_SECRET_ACCESS_KEY: \"{rnd(40, B64)}\"\n"),
         ("write", lambda: f"[profile backup]\nregion = eu-central-1\naws_secret_access_key={rnd(40, B64)}\n"),
         ("bash", lambda: f"aws configure set aws_secret_access_key {rnd(40, B64)} --profile backup")],
        [("write", lambda: "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"),
         ("write", lambda: "env:\n  AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}\n"),
         ("write", lambda: "aws_secret_access_key = <your-secret-access-key>\n"),
         ("bash", lambda: "export AWS_SECRET_ACCESS_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
         ("edit", lambda: "aws_secret_access_key=os.environ[\"AWS_SECRET_ACCESS_KEY\"],"),
         ("write", lambda: "AWS_SECRET_ACCESS_KEY: !Ref BackupUserSecretKey\n"),
         ("write", lambda: f"aws_secret_hash: {sha(40)}\n"),
         ("prompt", lambda: "AWS_SECRET_ACCESS_KEY=**************************************** in the job log, is that masked properly?"),
         ("write", lambda: f"spec:\n  encryptedData:\n    AWS_SECRET_ACCESS_KEY: {sealed_blob()}\n"),
         ("bash", lambda: "aws secretsmanager get-secret-value --secret-id prod/app/aws-secret --query SecretString"),
         ("mcp", lambda: "the aws secret key for the backup user is in 1Password under Infra/aws-backup"),
         ("write", lambda: "aws_secret_access_key = {{ aws_backup_secret_key }}\n")]),
    "azure-storage-key": (
        [("write", lambda: json.dumps({"ConnectionStrings": {"Blob": f"DefaultEndpointsProtocol=https;AccountName={acct()};AccountKey={storage_key()};EndpointSuffix=core.windows.net"}}, indent=2)),
         ("write", lambda: f"AZURE_STORAGE_CONNECTION_STRING=\"DefaultEndpointsProtocol=https;AccountName={acct()};AccountKey={storage_key()};EndpointSuffix=core.windows.net\"\n"),
         ("bash", lambda: f"az storage blob upload -f dump.sql -c backups -n dump.sql --connection-string 'DefaultEndpointsProtocol=https;AccountName={acct()};AccountKey={storage_key()}'"),
         ("edit", lambda: f"svc = BlobServiceClient.from_connection_string(\"DefaultEndpointsProtocol=https;AccountName={acct()};AccountKey={storage_key()};EndpointSuffix=core.windows.net\")"),
         ("prompt", lambda: f"why does this fail with 403? AccountName={acct()};AccountKey={storage_key()}"),
         ("mcp", lambda: f"storage conn string for the import job: DefaultEndpointsProtocol=https;AccountName={acct()};AccountKey={storage_key()};EndpointSuffix=core.windows.net"),
         ("write", lambda: f"stringData:\n  connection: \"DefaultEndpointsProtocol=https;AccountName={acct()};AccountKey={storage_key()};EndpointSuffix=core.windows.net\"\n"),
         ("write", lambda: f"<add name=\"Storage\" connectionString=\"DefaultEndpointsProtocol=https;AccountName={acct()};AccountKey={storage_key()}\" />\n")],
        [("write", lambda: "AZURE_STORAGE_CONNECTION_STRING=\"DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1\"\n"),
         ("write", lambda: f"conn: DefaultEndpointsProtocol=https;AccountName={acct()};AccountKey=<storage-account-key>;EndpointSuffix=core.windows.net\n"),
         ("write", lambda: f"conn: \"DefaultEndpointsProtocol=https;AccountName={acct()};AccountKey=${{STORAGE_KEY}}\"\n"),
         ("prompt", lambda: f"AccountName={acct()};AccountKey=****;EndpointSuffix=core.windows.net is what the portal shows"),
         ("write", lambda: "AzureWebJobsStorage=UseDevelopmentStorage=true\n"),
         ("edit", lambda: "conn = f\"DefaultEndpointsProtocol=https;AccountName={name};AccountKey={key}\""),
         ("write", lambda: f"BlobEndpoint=https://{acct()}.blob.core.windows.net/;SharedAccessSignature=sv=2022-11-02&sig=REDACTED\n"),
         ("bash", lambda: "az storage account keys list -g rg-prod -n stprod --query '[0].keyName' -o tsv")]),
    "private-key-base64": (
        [("write", lambda: f"apiVersion: v1\nkind: Secret\ntype: kubernetes.io/tls\ndata:\n  tls.crt: {b64('-----BEGIN CERTIFICATE-----' + chr(10) + pem_body(8) + chr(10) + '-----END CERTIFICATE-----')}\n  tls.key: {b64(pem('RSA '))}\n"),
         ("bash", lambda: f"echo {b64(pem('OPENSSH '))} | base64 -d > ~/.ssh/id_ed25519"),
         ("write", lambda: f"SSH_PRIVATE_KEY_B64={b64(pem('OPENSSH '))}\n"),
         ("write", lambda: json.dumps({"key": "SSH_PRIVATE_KEY", "value": b64(pem()), "masked": True})),
         ("prompt", lambda: f"set this as the GitLab CI variable DEPLOY_KEY: {b64(pem())}"),
         ("mcp", lambda: f"base64 of the signing key: {b64(pem(''))}"),
         ("edit", lambda: f"KEY_B64 = \"{b64(pem('EC '))}\""),
         ("write", lambda: f"users:\n- name: admin\n  user:\n    client-certificate-data: {b64('-----BEGIN CERTIFICATE-----' + chr(10) + pem_body(8) + chr(10) + '-----END CERTIFICATE-----')}\n    client-key-data: {b64(pem('EC '))}\n")],
        [("write", lambda: f"data:\n  tls.crt: {b64('-----BEGIN CERTIFICATE-----' + chr(10) + pem_body(12) + chr(10) + '-----END CERTIFICATE-----')}\n"),
         ("write", lambda: f"data:\n  key.pub: {b64('-----BEGIN PUBLIC KEY-----' + chr(10) + pem_body(6) + chr(10) + '-----END PUBLIC KEY-----')}\n"),
         ("write", lambda: f"tls.key: {b64('-----BEGIN PRIVATE KEY-----' + chr(10) + '...' + chr(10) + '-----END PRIVATE KEY-----')}\n"),
         ("bash", lambda: f"echo {b64('-----BEGIN PRIVATE KEY-----' + chr(10) + 'MIIE...your key here...' + chr(10) + '-----END PRIVATE KEY-----')} | base64 -d"),
         ("write", lambda: f"ca.crt: {b64('-----BEGIN CERTIFICATE-----' + chr(10) + pem_body(20) + chr(10) + '-----END CERTIFICATE-----')}\n"),
         ("prompt", lambda: "grep for LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t to find base64 encoded keys in the repo"),
         ("write", lambda: "client-key-data: ${CLIENT_KEY_DATA}\n"),
         ("edit", lambda: "key = base64.b64decode(os.environ[\"SSH_PRIVATE_KEY_B64\"])")]),
    "ntlm-authenticate": (
        [("bash", lambda: f"curl -v https://intranet.corp.example/ -H 'Authorization: NTLM {ntlm()}'"),
         ("prompt", lambda: f"the proxy log shows Authorization: NTLM {ntlm()} and then a 401, why?"),
         ("write", lambda: f"GET /ews/exchange.asmx HTTP/1.1\nHost: mail.corp.example\nAuthorization: NTLM {ntlm()}\n"),
         ("mcp", lambda: f"captured header: Proxy-Authorization: NTLM {ntlm(nt_len=R.choice([24, 120, 250]))}"),
         ("edit", lambda: f"HEADERS = {{\"Authorization\": \"NTLM {ntlm()}\"}}"),
         ("write", lambda: f"> Authorization: NTLM {ntlm(nt_len=R.randint(100, 300))}\n< HTTP/1.1 200 OK\n")],
        [("write", lambda: f"> Authorization: NTLM {ntlm(1)}\n< WWW-Authenticate: NTLM {ntlm(2)}\n"),
         ("prompt", lambda: f"why is the anonymous auth failing? Authorization: NTLM {ntlm(nt_len=0)}"),
         ("bash", lambda: "curl --ntlm -u \"CORP\\\\$USER:$PASS\" https://intranet.corp.example/"),
         ("write", lambda: "< HTTP/1.1 401 Unauthorized\n< WWW-Authenticate: Negotiate\n< WWW-Authenticate: NTLM\n"),
         ("edit", lambda: "auth = HttpNtlmAuth(f\"CORP\\\\{user}\", password)"),
         ("mcp", lambda: f"NTLM negotiate message from the client: {ntlm(1)}")]),
    "azure-sas-signature": (
        [("bash", lambda: f"azcopy copy ./dist 'https://{acct()}.blob.core.windows.net/$web?{sas()}' --recursive"),
         ("write", lambda: f"AZURE_STORAGE_SAS_TOKEN=\"?{sas()}\"\n"),
         ("write", lambda: f"BlobEndpoint=https://{acct()}.blob.core.windows.net/;SharedAccessSignature={sas()}\n"),
         ("prompt", lambda: f"download link for the export: https://{acct()}.blob.core.windows.net/exports/2026-10.csv?{sas()}"),
         ("edit", lambda: f"SAS_URL = \"https://{acct()}.blob.core.windows.net/backups?{sas()}\""),
         ("mcp", lambda: f"upload the logs here: https://{acct()}.blob.core.windows.net/support?{sas()}"),
         ("write", lambda: json.dumps({"sasUrl": f"https://{acct()}.queue.core.windows.net/jobs?{sas()}"}, indent=2)),
         ("bash", lambda: f"curl -X PUT -T report.pdf -H 'x-ms-blob-type: BlockBlob' \"https://{acct()}.blob.core.windows.net/r/report.pdf?{sas()}\"")],
        [("write", lambda: f"SAS_URL=https://{acct()}.blob.core.windows.net/c?{sas('<signature>')}\n"),
         ("write", lambda: f"url: \"https://{acct()}.blob.core.windows.net/c?{sas('REDACTED')}\"\n"),
         ("bash", lambda: f"azcopy copy ./dist \"https://{acct()}.blob.core.windows.net/web?${{SAS_TOKEN}}\" --recursive"),
         ("edit", lambda: f"url = f\"https://{{account}}.blob.core.windows.net/{{container}}?{{sas_token}}\""),
         ("prompt", lambda: f"the SAS looks like ?sv=2022-11-02&ss=b&sp=r&se=...&sig=... right?"),
         ("write", lambda: f"https://{acct()}.blob.core.windows.net/public/logo.png\n"),
         ("mcp", lambda: f"link (sig removed): https://{acct()}.blob.core.windows.net/exports/x.csv?sv=2022-11-02&sp=r&se=2027-01-01"),
         ("write", lambda: f"SAS_URL=https://{acct()}.blob.core.windows.net/c?{sas('x' * 46)}\n")]),
    "url-credentials": (
        [("write", lambda: f"DATABASE_URL=postgresql://app:{password()}@pg-{rnd(5, LOWDIG)}.prod.internal:5432/app\n"),
         ("bash", lambda: f"psql \"postgres://report:{password()}@10.20.{R.randint(0, 255)}.{R.randint(1, 254)}:5432/analytics\" -c '\\dt'"),
         ("write", lambda: f"spring:\n  data:\n    mongodb:\n      uri: mongodb+srv://svc:{password()}@cluster0.{rnd(5, LOWDIG)}.mongodb.net/app?retryWrites=true\n"),
         ("bash", lambda: f"git clone https://deploy:{opaque(url=True)}@git.example.org/acme/infra.git"),
         ("write", lambda: f"export HTTPS_PROXY=http://proxyuser:{password()}@proxy.corp.example:3128\n"),
         ("write", lambda: f"[global]\nindex-url = https://__token__:{opaque(url=True)}@pypi.example.org/simple\n"),
         ("prompt", lambda: f"the worker can't connect to amqp://celery:{password()}@rabbitmq.prod:5672/jobs, any idea?"),
         ("write", lambda: f"[alembic]\nsqlalchemy.url = mysql+pymysql://app:{password()}@db.example.org/app\n"),
         ("edit", lambda: f"REDIS_URL = \"redis://default:{password()}@redis-{R.randint(10000, 99999)}.cloud.example.com:6379\""),
         ("mcp", lambda: f"staging db: postgres://admin:{password()}@staging-db.example.org:5432/app"),
         ("bash", lambda: f"docker run -e DATABASE_URL=postgres://svc:{password()}@db.internal:5432/svc app:latest"),
         ("write", lambda: f"## Staging\n\nConnect with:\n\n```\nmongosh \"mongodb://root:{password()}@mongo.staging.example.org:27017/admin\"\n```\n")],
        [("write", lambda: "DATABASE_URL=postgres://app:${DB_PASSWORD}@db.prod.internal:5432/app\n"),
         ("write", lambda: "url: postgresql://{{ .Values.db.user }}:{{ .Values.db.password }}@{{ .Values.db.host }}/app\n"),
         ("edit", lambda: "url = f\"postgresql://{user}:{password}@{host}:{port}/{name}\""),
         ("bash", lambda: f"psql postgres://app:{password()}@localhost:5432/app_dev"),
         ("write", lambda: "MONGO_URL=mongodb://root:example@mongo:27017/\n"),
         ("prompt", lambda: "connection string format: postgres://<user>:<password>@<host>:5432/<db>"),
         ("mcp", lambda: "DB url is postgres://app:****@db.prod.internal:5432/app (password in 1Password)"),
         ("write", lambda: "REDIS_URL=redis://:changeme@redis:6379/0\n"),
         ("bash", lambda: "git clone https://oauth2:$(cat ~/.config/glab-token)@gitlab.com/acme/app.git"),
         ("edit", lambda: "DSN = \"mysql://%s:%s@%s/%s\" % (user, pw, host, db)"),
         ("write", lambda: f"SENTRY_DSN=https://{sha(32)}@o{R.randint(10**5, 10**6)}.ingest.sentry.io/{R.randint(10**6, 10**7)}\n"),
         ("write", lambda: "amqp_url: amqp://guest:guest@rabbitmq:5672/\n")]),
    "authorization-bearer": (
        [("bash", lambda: f"curl -s -H \"Authorization: Bearer {opaque()}\" https://api.example.org/v1/projects"),
         ("bash", lambda: f"http GET https://api.example.org/me 'Authorization:Bearer {opaque()}'"),
         ("edit", lambda: f"headers = {{\"Authorization\": \"Bearer {opaque()}\", \"Accept\": \"application/json\"}}"),
         ("write", lambda: f"const res = await fetch(url, {{ headers: {{ Authorization: 'Bearer {opaque()}' }} }});\n"),
         ("write", lambda: f"### list users\nGET https://api.example.org/users\nAuthorization: Bearer {opaque()}\n"),
         ("bash", lambda: f"curl -H 'Authorization: token {opaque()}' https://git.example.org/api/v1/repos"),
         ("bash", lambda: f"grpcurl -H 'authorization: Bearer {opaque()}' api.example.org:443 list"),
         ("prompt", lambda: f"this works in postman but not in the app: Bearer {opaque()}"),
         ("mcp", lambda: f"use header Authorization: Bearer {opaque()} for the partner API"),
         ("write", lambda: f"http:\n  headers:\n    Authorization: \"Bearer {opaque()}\"\n"),
         ("prompt", lambda: f"auth: token {opaque()}"),
         ("write", lambda: f"> GET /v1/me HTTP/2\n> authorization: Bearer {opaque()}\n< HTTP/2 200\n")],
        [("bash", lambda: "curl -H \"Authorization: Bearer $TOKEN\" https://api.example.org/v1/me"),
         ("edit", lambda: "headers = {\"Authorization\": f\"Bearer {token}\"}"),
         ("write", lambda: "Authorization: Bearer <your-access-token>\n"),
         ("write", lambda: "Authorization: Bearer {{token}}\n"),
         ("write", lambda: "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE\n"),
         ("prompt", lambda: "the log shows Authorization: Bearer [REDACTED] for every request"),
         ("write", lambda: "headers: { Authorization: 'Bearer ' + accessToken }\n"),
         ("write", lambda: "< WWW-Authenticate: Bearer realm=\"api\", error=\"invalid_token\"\n"),
         ("mcp", lambda: "the API uses bearer authentication as described in RFC 6750"),
         ("prompt", lambda: "token was sent as Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... and rejected"),
         ("write", lambda: "Authorization: Bearer xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"),
         ("bash", lambda: "curl -H \"Authorization: Bearer $(gcloud auth print-access-token)\" https://example.googleapis.com/v1/x")]),
    "authorization-basic": (
        [("bash", lambda: f"curl -H 'Authorization: Basic {basic('svc-' + rnd(4, LOWER), password())}' https://api.example.org/v1/export"),
         ("write", lambda: f"location /metrics {{\n  proxy_set_header Authorization \"Basic {basic('prometheus', password())}\";\n}}\n"),
         ("edit", lambda: f"headers = {{\"Authorization\": \"Basic {basic('api', opaque())}\"}}"),
         ("write", lambda: f"GET https://registry.example.org/v2/_catalog\nAuthorization: Basic {basic('bot', password())}\n"),
         ("bash", lambda: f"curl -H \"Authorization: ApiKey {basic(rnd(20, URLSAFE), rnd(22, URLSAFE))}\" https://es.example.org:9200/_cat/indices"),
         ("prompt", lambda: f"the webhook sends Authorization: Basic {basic('hook', password())}, can you verify it in the handler?"),
         ("mcp", lambda: f"partner creds header: Basic {basic('partner-' + rnd(3, LOWDIG), password())}"),
         ("write", lambda: f"const auth = 'Basic {basic('admin', password())}';\n")],
        [("bash", lambda: f"curl -H 'Authorization: Basic {basic('user', 'password')}' http://api.example.org"),
         ("write", lambda: f"Authorization: Basic {basic('admin', 'admin')}\n"),
         ("write", lambda: f"Authorization: Basic {basic('ci', '${REGISTRY_PASSWORD}')}\n"),
         ("write", lambda: "Authorization: Basic <base64 user:password>\n"),
         ("edit", lambda: "headers[\"Authorization\"] = \"Basic \" + base64.b64encode(f\"{user}:{pw}\".encode()).decode()"),
         ("prompt", lambda: "RFC 7617 example: Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="),
         ("mcp", lambda: "Use Basic authentication for the registry, credentials are in the vault"),
         ("write", lambda: "< WWW-Authenticate: Basic realm=\"Restricted\", charset=\"UTF-8\"\n"),
         ("bash", lambda: f"curl -H 'Authorization: Basic {basic('user', 'xxxxxxxxxxxx')}' https://api.example.org")]),
    "docker-config-auth": (
        [("write", lambda: json.dumps({"auths": {"registry.gitlab.com": {"auth": basic("deploy", password())}}}, indent=2)),
         ("bash", lambda: "echo '" + json.dumps({"auths": {"ghcr.io": {"auth": basic("bot", opaque())}}}) + "' > ~/.docker/config.json"),
         ("write", lambda: "apiVersion: v1\nkind: Secret\ntype: kubernetes.io/dockerconfigjson\nstringData:\n  .dockerconfigjson: '" + json.dumps({"auths": {"harbor.example.org": {"username": "robot", "auth": basic("robot$ci", password())}}}) + "'\n"),
         ("prompt", lambda: "my config.json is " + json.dumps({"auths": {"https://index.docker.io/v1/": {"auth": basic("acme", password())}}}) + " but pulls still fail"),
         ("write", lambda: json.dumps({"data": json.dumps({"auths": {"registry.example.org": {"auth": basic("ci", password())}}})})),
         ("mcp", lambda: "pull secret: " + json.dumps({"auths": {"registry.example.org": {"auth": basic("pull", password())}}})),
         ("edit", lambda: "DOCKER_AUTH_CONFIG = '" + json.dumps({"auths": {"registry.example.org:5000": {"auth": basic("svc", password())}}}) + "'")],
        [("write", lambda: json.dumps({"auths": {"ghcr.io": {}}, "credsStore": "desktop"}, indent=2)),
         ("write", lambda: json.dumps({"auths": {"registry.gitlab.com": {"auth": basic("gitlab-ci-token", "${CI_JOB_TOKEN}")}}})),
         ("write", lambda: json.dumps({"auths": {"registry.example.org": {"auth": "<base64 of user:token>"}}})),
         ("write", lambda: json.dumps({"auths": {"registry.example.org": {"auth": basic("username", "password")}}})),
         ("write", lambda: json.dumps({"auths": {"registry.example.org": {"auth": ""}}, "credHelpers": {"gcr.io": "gcloud"}})),
         ("edit", lambda: "cfg = {\"auths\": {host: {\"auth\": base64.b64encode(f\"{user}:{token}\".encode()).decode()}}}"),
         ("prompt", lambda: "the \"auth\" field is base64 of user:password, right?")]),
    "curl-user": (
        [("bash", lambda: f"curl -u admin:{password()} https://jenkins.example.org/api/json"),
         ("bash", lambda: f"curl -sk -u elastic:{password()} https://es.example.org:9200/_cluster/health"),
         ("bash", lambda: f"curl --user 'svc:{password()}' -X POST https://api.example.org/v1/import"),
         ("bash", lambda: f"curl --user=deploy:{opaque()} https://nexus.example.org/repository/raw/app.tgz -T app.tgz"),
         ("prompt", lambda: f"run curl -u ops:{password()} https://grafana.example.org/api/health for me"),
         ("write", lambda: f"#!/bin/sh\nset -e\ncurl -fsS -u backup:{password()} -T \"$1\" https://dav.example.org/backups/\n"),
         ("mcp", lambda: f"to test: curl -u partner:{password()} https://api.example.org/v1/ping"),
         ("bash", lambda: f"curl -u \"$USER:{opaque()}\" https://bitbucket.example.org/rest/api/1.0/projects")],
        [("bash", lambda: "curl -u \"admin:$ADMIN_PASSWORD\" https://jenkins.example.org/api/json"),
         ("bash", lambda: "curl -u elastic:${ELASTIC_PASSWORD} https://es.example.org:9200"),
         ("bash", lambda: "curl -u user:password https://httpbin.org/basic-auth/user/password"),
         ("bash", lambda: "curl -u elastic:changeme http://es:9200"),
         ("bash", lambda: "docker exec -u postgres:postgres db psql -c 'select 1'"),
         ("bash", lambda: "docker run --rm -u $(id -u):$(id -g) -v $PWD:/src app:latest"),
         ("bash", lambda: f"docker run -u {R.randint(1000, 1999)}:{R.randint(1000, 1999)} alpine id"),
         ("write", lambda: "curl -u \"$API_USER:$API_TOKEN\" \"$BASE_URL/export\" -o out.json\n"),
         ("prompt", lambda: "curl -u <user>:<api-token> https://example.atlassian.net/rest/api/3/myself")]),
    "cli-password-flag": (
        [("bash", lambda: f"helm repo add acme https://charts.example.org --username ci --password {password()}"),
         ("bash", lambda: f"kubectl config set-credentials deployer --token={opaque()}"),
         ("bash", lambda: f"argocd login argocd.example.org --username admin --password '{password()}'"),
         ("bash", lambda: f"doctl auth init --access-token {opaque()}"),
         ("bash", lambda: f"influx setup --org acme --bucket metrics --username admin --password {password()} --token {opaque()} --force"),
         ("bash", lambda: f"sentry-cli --auth-token {opaque()} releases new 1.4.2"),
         ("bash", lambda: f"az ad sp create-for-rbac -n ci && az login --service-principal --username {uuid()} --client-secret {opaque()} --tenant {uuid()}"),
         ("prompt", lambda: f"why does `glab auth login --hostname git.example.org --token {opaque()}` say unauthorized?"),
         ("write", lambda: f"#!/bin/sh\nexec ./server --db-password={password()} --listen :8080\n"),
         ("mcp", lambda: f"deploy cmd: ./deploy.sh --env prod --api-key {opaque()}"),
         ("edit", lambda: f"CMD [\"./worker\", \"--queue\", \"jobs\", \"--secret={opaque()}\"]"),
         ("bash", lambda: f"vault login -method=userpass username=ci -password {password()}")],
        [("bash", lambda: "helm repo add acme https://charts.example.org --username ci --password \"$HELM_PASSWORD\""),
         ("bash", lambda: "echo \"$CI_REGISTRY_PASSWORD\" | docker login --password-stdin -u ci registry.example.org"),
         ("bash", lambda: "kubectl --token=\"$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\" get pods"),
         ("bash", lambda: "glab auth login --token ${GITLAB_TOKEN} --hostname git.example.org"),
         ("write", lambda: "  --password string     Password for the registry\n  --token string        Bearer token\n"),
         ("bash", lambda: "./server --db-password-file /run/secrets/db --token-ttl 3600"),
         ("bash", lambda: "argocd login argocd.example.org --username admin --password <admin-password>"),
         ("bash", lambda: "app --api-key ******** --verbose"),
         ("bash", lambda: "kubectl create secret generic app --from-literal=user=svc --secret-name app-creds"),
         ("bash", lambda: "mytool --client-secret-file ./client_secret.json --token-file ~/.config/mytool/token"),
         ("bash", lambda: "terraform apply -var \"db_password=$TF_VAR_db_password\""),
         ("prompt", lambda: "pass --api-key GITLAB_API_KEY so it reads from the env")]),
    "securestring-literal": (
        [("write", lambda: f"$pw = ConvertTo-SecureString '{password()}' -AsPlainText -Force\n$cred = New-Object PSCredential('svc-backup', $pw)\n"),
         ("bash", lambda: f"pwsh -c \"\\$p = ConvertTo-SecureString \\\"{password()}\\\" -AsPlainText -Force; Connect-AzAccount -Credential (New-Object PSCredential('{uuid()}', \\$p))\""),
         ("edit", lambda: f"$secure = ConvertTo-SecureString -String \"{password()}\" -AsPlainText -Force"),
         ("prompt", lambda: f"ConvertTo-SecureString \"{password()}\" -AsPlainText -Force fails on the build agent, why?"),
         ("mcp", lambda: f"snippet for the runbook: $p = ConvertTo-SecureString '{password()}' -AsPlainText -Force"),
         ("write", lambda: f"Set-ADAccountPassword -Identity jdoe -NewPassword (ConvertTo-SecureString \"{password()}\" -AsPlainText -Force) -Reset\n")],
        [("write", lambda: "$pw = ConvertTo-SecureString $env:SVC_PASSWORD -AsPlainText -Force\n"),
         ("write", lambda: "$secure = Read-Host -AsSecureString | ConvertFrom-SecureString\n"),
         ("write", lambda: "$pw = Get-Content .\\pw.txt | ConvertTo-SecureString\n"),
         ("write", lambda: "$pw = ConvertTo-SecureString \"<password>\" -AsPlainText -Force\n"),
         ("write", lambda: "$pw = ConvertTo-SecureString \"P@ssw0rd!\" -AsPlainText -Force\n"),
         ("write", lambda: "$pw = ConvertTo-SecureString \"${{ secrets.SVC_PASSWORD }}\" -AsPlainText -Force\n"),
         ("prompt", lambda: "should I use ConvertTo-SecureString -AsPlainText or Get-Credential here?")]),
    "curl-setopt": (
        [("edit", lambda: f"curl_setopt($ch, CURLOPT_USERPWD, \"api:{password()}\");"),
         ("write", lambda: f"<?php\n$ch = curl_init($url);\ncurl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);\ncurl_setopt($ch, CURLOPT_USERPWD, \"svc:{password()}\");\n"),
         ("write", lambda: f"curl_easy_setopt(curl, CURLOPT_USERPWD, \"ftpuser:{password()}\");\n"),
         ("edit", lambda: f"curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, \"{opaque()}\");"),
         ("write", lambda: f"curl_easy_setopt(h, CURLOPT_PASSWORD, \"{password()}\");\n"),
         ("prompt", lambda: f"curl_setopt($ch, CURLOPT_PROXYUSERPWD, \"proxy:{password()}\"); gives 407, why?"),
         ("edit", lambda: f"curl_setopt($ch, CURLOPT_USERPWD, '{rnd(6, LOWER)}:{password()}');")],
        [("edit", lambda: "curl_setopt($ch, CURLOPT_USERPWD, $user . ':' . $pass);"),
         ("edit", lambda: "curl_setopt($ch, CURLOPT_USERPWD, \"$user:$password\");"),
         ("edit", lambda: "curl_setopt($ch, CURLOPT_USERPWD, \"{$this->user}:{$this->pass}\");"),
         ("write", lambda: "curl_easy_setopt(curl, CURLOPT_USERPWD, \"user:password\");\n"),
         ("write", lambda: "snprintf(buf, sizeof buf, \"%s:%s\", user, pass);\ncurl_easy_setopt(curl, CURLOPT_USERPWD, buf);\n"),
         ("edit", lambda: "curl_setopt($ch, CURLOPT_PASSWORD, getenv('FTP_PASSWORD'));"),
         ("write", lambda: "curl_easy_setopt(curl, CURLOPT_PASSWORD, \"<your password>\");\n")]),
    "short-password-flag": (
        [("bash", lambda: f"mysql -h db.prod.internal -u app -p{password()} app -e 'show tables'"),
         ("bash", lambda: f"mysql -uroot -p'{password()}' -h 10.0.{R.randint(0, 9)}.{R.randint(2, 250)}"),
         ("bash", lambda: f"mysqldump --single-transaction -u backup -p\"{password()}\" shop | gzip > shop.sql.gz"),
         ("bash", lambda: f"kubectl exec -it mariadb-0 -- mariadb -uroot -p{password()}"),
         ("bash", lambda: f"mongosh mongodb://db.internal:27017/admin -u admin -p'{password()}'"),
         ("write", lambda: f"#!/bin/sh\nmysqldump -u backup -p{password()} --all-databases > /backup/all.sql\n"),
         ("prompt", lambda: f"`mysql -u report -p{password()} analytics` gives access denied"),
         ("mcp", lambda: f"restore with: mysql -u root -p'{password()}' shop < dump.sql"),
         ("bash", lambda: f"docker login -u bot -p{opaque()} registry.example.org")],
        [("bash", lambda: "mysql -u root -p app"),
         ("bash", lambda: "mysql -uroot -p$MYSQL_ROOT_PASSWORD -e 'select 1'"),
         ("bash", lambda: "mysql -u app -p\"${DB_PASSWORD}\" app"),
         ("bash", lambda: "mysqldump -u backup -p --all-databases > all.sql"),
         ("bash", lambda: f"docker run --name mysql -p3306:3306 -e MYSQL_ROOT_PASSWORD_FILE=/run/secrets/db mysql:8"),
         ("bash", lambda: "mysql -h db -P 3306 -u app -pchangeme app"),
         ("bash", lambda: "mongosh --host db --port 27017 -u admin -p --authenticationDatabase admin"),
         ("bash", lambda: "docker login -u bot -p $CI_REGISTRY_PASSWORD registry.example.org")]),
    "sshpass": (
        [("bash", lambda: f"sshpass -p '{password()}' ssh -o StrictHostKeyChecking=no root@10.0.{R.randint(0, 9)}.{R.randint(2, 250)}"),
         ("bash", lambda: f"sshpass -p {password()} scp backup.tar.gz admin@nas.example.org:/volume1/backup/"),
         ("bash", lambda: f"rsync -az -e \"sshpass -p {password()} ssh\" ./dist/ deploy@web01.example.org:/srv/app/"),
         ("write", lambda: f"#!/bin/sh\nsshpass -p\"{password()}\" ssh ops@switch01 'show running-config'\n"),
         ("prompt", lambda: f"sshpass -p '{password()}' ssh pi@192.168.2.40 hangs, why?"),
         ("mcp", lambda: f"to get in: sshpass -p '{password()}' ssh admin@bastion.example.org")],
        [("bash", lambda: "sshpass -e ssh deploy@web01.example.org"),
         ("bash", lambda: "sshpass -f ~/.config/nas-pw scp backup.tar.gz admin@nas:/backup/"),
         ("bash", lambda: "sshpass -p \"$SSHPASS\" ssh root@10.0.0.7"),
         ("bash", lambda: "sshpass -p password ssh user@host"),
         ("bash", lambda: "sshpass -p raspberry ssh pi@raspberrypi.local"),
         ("write", lambda: "sshpass -p '<password>' ssh admin@<host>\n"),
         ("bash", lambda: "sshpass -p \"$(op read op://Infra/nas/password)\" ssh admin@nas")]),
    "prose-secret": (
        [("prompt", lambda: f"the staging admin password is {password()}"),
         ("prompt", lambda: f"api key = {opaque()} for the partner sandbox"),
         ("mcp", lambda: f"new token: {opaque()} (old one is revoked)"),
         ("prompt", lambda: f"het wachtwoord is {password()} voor de nas"),
         ("write", lambda: f"# Staging access\n\n- url: https://staging.example.org\n- user: admin\n- password: {password()}\n"),
         ("prompt", lambda: f"password: `{password()}` user: ops"),
         ("mcp", lambda: f"the passphrase is {password()} for the backup key"),
         ("prompt", lambda: f"secret is {opaque()}, set it as WEBHOOK_SECRET"),
         ("edit", lambda: f"# deploy notes: api key is {opaque()} until the rotation on Friday"),
         ("mcp", lambda: f"wifi gasten: wachtwoord is {password()}"),
         ("prompt", lambda: f"use this token: {opaque()}"),
         ("write", lambda: f"Release checklist\n1. log in as release-bot, password was {password()}\n2. tag the build\n")],
        [("prompt", lambda: "the password is required for the staging login"),
         ("prompt", lambda: "token is expired again, can you check the refresh flow?"),
         ("mcp", lambda: "the secret is stored in 1Password under Infra/staging"),
         ("prompt", lambda: "password is ******** in the screenshot, so it's masked"),
         ("prompt", lambda: "api key: see the CI variables in the project settings"),
         ("mcp", lambda: "token: <redacted>, rotated after the incident"),
         ("prompt", lambda: "the password is stored at ~/.pgpass so psql picks it up"),
         ("prompt", lambda: "password is P@ssw0rd! in all the tutorials, that's why it gets brute forced"),
         ("prompt", lambda: "token: ${GITLAB_TOKEN} should expand in the job"),
         ("prompt", lambda: "the password was incorrect three times, the account is locked"),
         ("mcp", lambda: "wachtwoord is verlopen, graag resetten"),
         ("prompt", lambda: "the token is GITLAB_TOKEN from the env, not the bot one"),
         ("prompt", lambda: "secret is mounted at /var/run/secrets/app/token")]),
    "generic-assignment": (
        [("write", lambda: f"STRIPE_WEBHOOK_SIGNING_KEY={opaque()}\nAPP_ENV=production\n"),
         ("write", lambda: f"oauth:\n  client_id: {uuid()}\n  client_secret: {opaque()}\n"),
         ("write", lambda: json.dumps({"apiKey": opaque(), "region": "eu-west-1"}, indent=2)),
         ("write", lambda: f"[service]\napi_key = \"{opaque()}\"\ntimeout = 30\n"),
         ("edit", lambda: f"config.secret_key_base = \"{sha(128)}\""),
         ("edit", lambda: f"const signingKey = \"{opaque()}\""),
         ("edit", lambda: f"webhookSecret := \"{opaque()}\""),
         ("edit", lambda: f"'password' => '{password()}',"),
         ("write", lambda: f"services:\n  db:\n    image: postgres:16\n    environment:\n      - POSTGRES_PASSWORD={password()}\n"),
         ("write", lambda: f"app.jwt.secret={opaque()}\nserver.port=8080\n"),
         ("bash", lambda: f"export ENCRYPTION_KEY={sha(64)}"),
         ("prompt", lambda: f"set MASTER_KEY={opaque()} in the env and restart"),
         ("mcp", lambda: f"credentials={password()} for the ftp drop"),
         ("write", lambda: f"variable \"x\" {{}}\nclient_secret = \"{opaque()}\"\n")],
        [("write", lambda: "token_type = \"bearer\"\napi_key_header = \"X-API-Key\"\n"),
         ("write", lambda: "secret_name: prod-db-credentials\npassword_min_length: 12\n"),
         ("write", lambda: f"PASSWORD_HASH=\"$2b$12${rnd(53, A62 + './')}\"\n"),
         ("edit", lambda: "token = generate_token(user, scopes=[\"read\"])"),
         ("write", lambda: "api_key: ${API_KEY}\nclient_secret: \"{{ vault_client_secret }}\"\n"),
         ("write", lambda: "secret: !Ref DbSecret\npassword: \"<%= ENV['DB_PASSWORD'] %>\"\n"),
         ("edit", lambda: "SECRET_KEY = os.environ[\"SECRET_KEY\"]"),
         ("write", lambda: f"api_key_id: {uuid()}\ntoken_hash: {sha()}\n"),
         ("write", lambda: "credentials_path: /etc/app/credentials.json\nsecret_key_ref: app-secrets\n"),
         ("edit", lambda: "apiKey: process.env.PARTNER_API_KEY,"),
         ("write", lambda: "auth_token_ttl: 3600\ntoken_url: https://auth.example.org/oauth/token\n"),
         ("edit", lambda: "signingKey: signingKeyFromEnv,"),
         ("write", lambda: "masterKey: \"test-master-key-not-real\"\nencryption_key: \"0000000000000000\"\n"),
         ("write", lambda: "password: \"{{ lookup('env', 'DB_PASSWORD') }}\"\nprivate_key: |\n"),
         ("write", lambda: "SECRET_KEY_BASE: <%= Rails.application.credentials.secret_key_base %>\n")]),
}


# --------------------------------------------------------------------------- events


def event(kind, text):
    if kind == "prompt":
        return {"hook_event_name": "UserPromptSubmit", "prompt": text}
    if kind == "bash":
        return {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": text, "description": "run"}}
    if kind == "write":
        return {"hook_event_name": "PreToolUse", "tool_name": "Write", "tool_input": {"file_path": "/tmp/x/config", "content": text}}
    if kind == "edit":
        return {"hook_event_name": "PreToolUse", "tool_name": "Edit", "tool_input": {"file_path": "/tmp/x/app.py", "old_string": "TOKEN = None", "new_string": text}}
    if kind == "mcp":
        return {"hook_event_name": "PreToolUse", "tool_name": "mcp__claude_ai_Slack__slack_send_message", "tool_input": {"channel_id": "C0123", "message": text}}
    raise ValueError(kind)


def main():
    n = 0

    def emit(label, kind, family, text):
        nonlocal n
        n += 1
        print(json.dumps({"id": n, "label": label, "kind": kind, "family": family, "event": event(kind, text)}))

    for family, gen in TOKENS.items():
        for kind, tmpl in TOKEN_CONTEXTS:
            for _ in range(2):
                emit("secret", kind, family, tmpl.format(t=gen()))
    for kind, tmpl in PASSWORD_CONTEXTS:
        for _ in range(12):
            emit("secret", kind, "password", tmpl.format(p=password()))
    for family, gen in SPECIAL_POSITIVES:
        for kind in ("prompt", "bash", "write", "mcp"):
            for _ in range(6):
                emit("secret", kind, family, gen())

    for rule, (positives, negatives) in RULE_FAMILIES.items():
        for label, cases in (("secret", positives), ("clean", negatives)):
            for _ in range(-(-70 // len(cases))):
                for kind, gen in cases:
                    emit(label, kind, f"ctx-{rule}", gen())

    for family, gen in CLEAN:
        for kind in ("prompt", "bash", "write", "edit", "mcp"):
            for _ in range(4):
                emit("clean", kind, family, gen())

    # old_string carries the secret (already in the file); only new_string is the tool's payload
    for _ in range(40):
        t = TOKENS[R.choice(list(TOKENS))]()
        ev = event("edit", "TOKEN = os.environ[\"TOKEN\"]")
        ev["tool_input"]["old_string"] = f"TOKEN = \"{t}\""
        n += 1
        print(json.dumps({"id": n, "label": "clean", "kind": "edit", "family": "edit-removes-secret", "event": ev}))


if __name__ == "__main__":
    main()
