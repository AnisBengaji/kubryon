#!/bin/bash
# generate_dataset_v6.sh
#
# Fixes vs v5:
#   - Appends (not overwrites) ground_truth_log.csv -> multiple runs joinable
#   - Logs start AND end timestamp of each action, plus run_id, pod, expected_rule
#   - Adds a BENIGN pool (same commands attackers use, but legitimate context:
#     right after pod creation, or normal admin usage) so the model sees
#     non-attack alert-producing behavior, not just silence
#   - Uses fresh pods per run (suffixed with RUN_ID) to vary pod age
#   - Logs pod creation time explicitly, so pod_age_seconds can be computed later
#
# v6.1 addition: self-healing pod check before every attack/benign action.
# With the engine enforcing real kill/isolate thresholds, a pod can be
# deleted by the engine mid-session. Previously this caused every remaining
# action in the session to fail with "pod not found" and corrupted ground
# truth (logged as if it ran, but nothing executed). ensure_pod_alive()
# recreates the pod on demand and logs the respawn as its own ground-truth
# event -- also means pod_age_seconds correctly resets after a real kill,
# matching what a Deployment respawn looks like in production.
#
# Usage: bash generate_dataset_v6.sh <run_id>
#   e.g.: bash generate_dataset_v6.sh run7

RUN_ID="${1:?Usage: generate_dataset_v6.sh <run_id>}"
TOTAL_ROUNDS=15
MIN_PAUSE=30
MAX_PAUSE=100
INITIAL_IDLE=180
FINAL_IDLE=180
GROUND_TRUTH_LOG="ground_truth_log.csv"

POD_ATTACK="test-pod-${RUN_ID}"
POD_APT="test-pod-apt-${RUN_ID}"

log() { echo -e "\n==================================================\n  $1\n=================================================="; }
gt_now() { date -u +"%Y-%m-%dT%H:%M:%S.%3N"; }

# columns: run_id,start_utc,end_utc,label,type,pod,expected_rule,detail
log_gt() {
    echo "${RUN_ID},${1},${2},${3},${4},${5},${6},${7}" >> "$GROUND_TRUTH_LOG"
}

random_pause() {
    local secs=$(( (RANDOM % (MAX_PAUSE - MIN_PAUSE + 1)) + MIN_PAUSE ))
    log "Idle period (~${secs}s)"
    sleep "$secs"
}

create_pod() {
    local pod_name=$1 image=$2
    kubectl delete pod "$pod_name" --force --grace-period=0 --ignore-not-found &>/dev/null
    sleep 2
    kubectl run "$pod_name" --image="$image" --restart=Never -- sleep 21600
    kubectl wait --for=condition=Ready "pod/$pod_name" --timeout=90s || { echo "ERROR: $pod_name not ready"; exit 1; }
    local created_at; created_at=$(gt_now)
    log_gt "$created_at" "$created_at" "meta" "pod_created" "$pod_name" "" "image:$image"
}

ensure_pods() {
    log "Creating fresh pods for $RUN_ID"
    create_pod "$POD_ATTACK" busybox
    create_pod "$POD_APT" ubuntu
}

# pod_name -> image, used by ensure_pod_alive() to respawn with the right image
declare -A POD_IMAGE
POD_IMAGE["$POD_ATTACK"]="busybox"
POD_IMAGE["$POD_APT"]="ubuntu"

# Check the pod is Running right before using it; if the engine killed it
# (real kill action, or it crashed/evicted), recreate it and log the
# respawn as its own ground-truth event so pod_age_seconds stays accurate.
ensure_pod_alive() {
    local pod_name=$1
    local phase
    phase=$(kubectl get pod "$pod_name" -o jsonpath='{.status.phase}' 2>/dev/null)
    if [ "$phase" == "Running" ]; then
        return 0
    fi
    echo "  !! $pod_name not Running (phase='${phase:-gone}') -- respawning"
    log_gt "$(gt_now)" "$(gt_now)" "meta" "pod_respawned" "$pod_name" "" "was_phase:${phase:-gone}"
    create_pod "$pod_name" "${POD_IMAGE[$pod_name]}"
}

# ---------------------------------------------------------
# Timed action wrapper: logs start/end around any command
# ---------------------------------------------------------
run_action() {
    local label=$1 type=$2 pod=$3 expected_rule=$4 detail=$5; shift 5
    ensure_pod_alive "$pod"
    local t0; t0=$(gt_now)
    "$@"
    local t1; t1=$(gt_now)
    log_gt "$t0" "$t1" "$label" "$type" "$pod" "$expected_rule" "$detail"
}

# ---------------------------------------------------------
# ATTACK pool -- malicious context (pod already "compromised")
# ---------------------------------------------------------
a_shell()          { run_action attack shell "$POD_ATTACK" "Terminal shell in container" "" \
                        kubectl exec "$POD_ATTACK" -- sh -c "echo test"; }
a_sensitive_file() { run_action attack sensitive_file "$POD_ATTACK" "Read sensitive file untrusted" "" \
                        kubectl exec "$POD_ATTACK" -- cat /etc/shadow; }
a_suid()           { run_action attack suid "$POD_ATTACK" "Set Setuid or Setgid bit" "" \
                        kubectl exec "$POD_ATTACK" -- sh -c "chmod u+s /bin/busybox; chmod u-s /bin/busybox"; }
a_k8s_api()        { run_action attack k8s_api "$POD_APT" "Contact K8S API Server From Container" "" \
                        kubectl exec "$POD_APT" -- curl -k -s -m 5 https://kubernetes.default.svc; }
a_binary_drop()    { run_action attack binary_drop "$POD_ATTACK" "Drop and execute new binary in container" "" \
                        kubectl exec "$POD_ATTACK" -- sh -c 'cp /bin/busybox /tmp/tool_$$ && /tmp/tool_$$ ls'; }
a_write_root()     { run_action attack write_root "$POD_ATTACK" "Write below root" "" \
                        kubectl exec "$POD_ATTACK" -- sh -c "echo x > /malicious_$RANDOM"; }
a_shell_config()   { run_action attack shell_config "$POD_APT" "Modify Shell Configuration File" "" \
                        kubectl exec "$POD_APT" -- sh -c "echo 'alias ls=rm' >> /root/.bashrc"; }
a_clear_history()  { run_action attack clear_history "$POD_APT" "Delete or rename shell history" "" \
                        kubectl exec "$POD_APT" -- sh -c "rm -f /root/.bash_history"; }
a_ssh_info()       { run_action attack ssh_info "$POD_APT" "Read ssh information" "" \
                        kubectl exec "$POD_APT" -- sh -c "mkdir -p /root/.ssh && cat /root/.ssh/id_rsa 2>/dev/null"; }
a_rsync()          { run_action attack rsync "$POD_APT" "Launch Ingress Remote File Copy Tools in Container" "" \
                        kubectl exec "$POD_APT" -- rsync --version; }
a_env_privesc()    { run_action attack env_privesc "$POD_APT" "Potential Local Privilege Escalation via Environment Variables Misuse" "" \
                        kubectl exec "$POD_APT" -- sh -c "GLIBC_TUNABLES=glibc.cpu.hwcaps=SHSTK ls"; }
a_pkg_mgmt_late()  { run_action attack pkg_mgmt_late "$POD_APT" "Launch Package Management Process in Container" "late(pod already old)" \
                        kubectl exec "$POD_APT" -- apt-get update -qq; }

ATTACK_POOL=(a_shell a_sensitive_file a_suid a_k8s_api a_binary_drop a_write_root \
             a_shell_config a_clear_history a_ssh_info a_rsync a_env_privesc a_pkg_mgmt_late)

# ---------------------------------------------------------
# BENIGN pool -- same/similar syscalls, legitimate context.
# Run right after pod creation (build-time) or as routine admin ops.
# ---------------------------------------------------------
b_pkg_install_fresh() { ensure_pod_alive "$POD_APT"
                         kubectl exec "$POD_APT" -- apt-get update -qq
                         run_action benign pkg_mgmt_fresh "$POD_APT" "Launch Package Management Process in Container" "fresh_pod_setup" \
                            kubectl exec "$POD_APT" -- apt-get install -y -qq curl rsync; }
b_routine_ls()        { run_action benign routine_read "$POD_APT" "" "admin_inspection" \
                            kubectl exec "$POD_APT" -- ls -la /etc; }
b_routine_curl()      { run_action benign routine_network "$POD_APT" "" "healthcheck" \
                            kubectl exec "$POD_APT" -- curl -s -m 5 -o /dev/null http://example.com; }
b_readonly_config()   { run_action benign config_read "$POD_APT" "" "admin_inspection" \
                            kubectl exec "$POD_APT" -- cat /etc/hostname; }

BENIGN_POOL=(b_routine_ls b_routine_curl b_readonly_config)

# ---------------------------------------------------------
# Round runner
# ---------------------------------------------------------
run_variable_round() {
    local round=$1
    local roll=$(( RANDOM % 100 ))
    local subset_size

    if   [ $roll -lt 15 ]; then subset_size=0
    elif [ $roll -lt 40 ]; then subset_size=$(( (RANDOM % 3) + 1 )); local pool=(BENIGN_POOL)
    elif [ $roll -lt 70 ]; then subset_size=$(( (RANDOM % 3) + 1 )); local pool=(ATTACK_POOL)
    elif [ $roll -lt 90 ]; then subset_size=$(( (RANDOM % 3) + 4 )); local pool=(ATTACK_POOL)
    else                        subset_size=$(( (RANDOM % 3) + 7 )); local pool=(ATTACK_POOL)
    fi

    if [ "$subset_size" -eq 0 ]; then
        log "Round $round/$TOTAL_ROUNDS -- IDLE"
        log_gt "$(gt_now)" "$(gt_now)" "idle" "idle_round" "" "" "round_${round}"
        return
    fi

    local -n src="${pool[0]}"
    local chosen=($(printf "%s\n" "${src[@]}" | shuf -n "$subset_size" 2>/dev/null || printf "%s\n" "${src[@]}"))
    log "Round $round/$TOTAL_ROUNDS -- ${pool[0]} x${subset_size}: ${chosen[*]}"

    for fn in "${chosen[@]}"; do
        echo "  -> $fn"
        $fn
        sleep $(( (RANDOM % 6) + 1 ))
    done
}

# ---------------------------------------------------------
# Main
# ---------------------------------------------------------
if [ ! -f "$GROUND_TRUTH_LOG" ]; then
    echo "run_id,start_utc,end_utc,label,type,pod,expected_rule,detail" > "$GROUND_TRUTH_LOG"
fi

ensure_pods

log "Initial idle (~${INITIAL_IDLE}s)"
log_gt "$(gt_now)" "$(gt_now)" "idle" "idle_start" "" "" "initial_idle"
sleep "$INITIAL_IDLE"
log_gt "$(gt_now)" "$(gt_now)" "idle" "idle_end" "" "" "initial_idle"

# one fresh-pod-setup benign package install, deliberately right after creation
b_pkg_install_fresh

for i in $(seq 1 $TOTAL_ROUNDS); do
    run_variable_round $i
    random_pause
done

log "Final idle (~${FINAL_IDLE}s)"
log_gt "$(gt_now)" "$(gt_now)" "idle" "idle_start" "" "" "final_idle"
sleep "$FINAL_IDLE"
log_gt "$(gt_now)" "$(gt_now)" "idle" "idle_end" "" "" "final_idle"

log "Run $RUN_ID complete. Ground truth appended to $GROUND_TRUTH_LOG"
echo "Repeat with a new run_id (e.g. run8, run9...) to build up more groups for train/test splitting."
