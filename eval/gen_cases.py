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
import sys

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
    "paserk-key": lambda: f"k{R.randint(1, 4)}.{R.choice(['local', 'secret', 'secret-pw'])}.{rnd(R.choice([43, 86, 150]), URLSAFE)}",
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
