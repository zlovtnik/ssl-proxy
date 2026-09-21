#!/usr/bin/env bash
set -Eeuo pipefail

# A topic is only trimmed after every selected topic has produced a valid plan.
# The PostgreSQL gate requires offset-linked ingestion evidence, not a sample or
# an aggregate coverage estimate.

: "${TOPICS_FILE:=/config/topics.tsv}"
: "${DRY_RUN:=true}"
: "${ACTIVE_TOPICS:=*}"
: "${IGNORE_GROUPS:=}"
: "${MAX_TRIM_FRACTION:=0.90}"
: "${PG_MAX_STALE_MIN:=60}"
: "${ALLOW_UNPROJECTED_BEFORE_EPOCH:=}"
: "${RPK_TIMEOUT_SECONDS:=30}"
: "${PUSHGATEWAY_URL:=}"

readonly STATUS_OK=0
readonly STATUS_NOTHING=1
readonly STATUS_GROUP_BLOCKED=10
readonly STATUS_PARSE_ERROR=11
readonly STATUS_GATE_STALE=12
readonly STATUS_GATE_COVERAGE=13
readonly STATUS_GATE_FLOOR=14
readonly STATUS_BREAKER=15
readonly STATUS_CONSUME_ERROR=16
readonly STATUS_TRIM_ERROR=17

declare -A topic_status=()
declare -A topic_trim_records=()
declare -A topic_records=()
declare -a selected_topics=()

work_dir="$(mktemp -d /tmp/redpanda-maint.XXXXXX)"
started_at="$(date +%s)"
failed_topics=0
run_success=0

log() {
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

die() {
  log "fatal: $*" >&2
  exit 1
}

is_true() {
  case "$1" in
    true|TRUE|1|yes|YES) return 0 ;;
    false|FALSE|0|no|NO) return 1 ;;
    *) return 2 ;;
  esac
}

csv_contains() {
  local csv="$1" needle="$2" item
  local -a items=()
  IFS=',' read -r -a items <<<"$csv"
  for item in "${items[@]}"; do
    [[ "$item" == "$needle" ]] && return 0
  done
  return 1
}

topic_is_active() {
  [[ "$ACTIVE_TOPICS" == "*" ]] || csv_contains "$ACTIVE_TOPICS" "$1"
}

metric_label() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

push_metrics() {
  local exit_code=$? now payload success_payload topic status
  now="$(date +%s)"
  payload="$work_dir/metrics.prom"
  {
    printf '# TYPE redpanda_maint_last_run_timestamp_seconds gauge\n'
    printf 'redpanda_maint_last_run_timestamp_seconds %s\n' "$now"
    printf '# TYPE redpanda_maint_dry_run gauge\n'
    if is_true "$DRY_RUN"; then printf 'redpanda_maint_dry_run 1\n'; else printf 'redpanda_maint_dry_run 0\n'; fi
    printf '# TYPE redpanda_maint_failed_topics gauge\n'
    printf 'redpanda_maint_failed_topics %s\n' "$failed_topics"
    printf '# TYPE redpanda_maint_topic_status gauge\n'
    printf '# TYPE redpanda_maint_trim_records gauge\n'
    printf '# TYPE redpanda_maint_topic_records gauge\n'
    for topic in "${selected_topics[@]}"; do
      status="${topic_status[$topic]:-$STATUS_PARSE_ERROR}"
      printf 'redpanda_maint_topic_status{topic="%s"} %s\n' "$(metric_label "$topic")" "$status"
      printf 'redpanda_maint_trim_records{topic="%s"} %s\n' "$(metric_label "$topic")" "${topic_trim_records[$topic]:-0}"
      printf 'redpanda_maint_topic_records{topic="%s"} %s\n' "$(metric_label "$topic")" "${topic_records[$topic]:-0}"
    done
  } >"$payload"
  if [[ -n "$PUSHGATEWAY_URL" ]]; then
    curl --fail --silent --show-error --max-time 15 \
      --data-binary "@$payload" "${PUSHGATEWAY_URL%/}/metrics/job/redpanda-maint/run/current" \
      || log "warning: failed to push metrics" >&2
    if [[ "$run_success" == 1 ]]; then
      success_payload="$work_dir/success.prom"
      printf '# TYPE redpanda_maint_last_success_timestamp_seconds gauge\nredpanda_maint_last_success_timestamp_seconds %s\n' "$now" >"$success_payload"
      curl --fail --silent --show-error --max-time 15 \
        --data-binary "@$success_payload" "${PUSHGATEWAY_URL%/}/metrics/job/redpanda-maint/run/success" \
        || log "warning: failed to push success metric" >&2
    fi
  fi
  rm -rf "$work_dir"
  return "$exit_code"
}
trap push_metrics EXIT

mark_failed() {
  local topic="$1" status="$2" message="$3"
  if (( ${topic_status[$topic]:-0} < 10 )); then
    failed_topics=$((failed_topics + 1))
  fi
  topic_status[$topic]="$status"
  log "topic=$topic status=$status blocked=$message" >&2
}

require_uint() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

rpk_run() {
  timeout "${RPK_TIMEOUT_SECONDS}s" rpk "$@"
}

offset_at_epoch() {
  local topic="$1" partition="$2" epoch="$3" hwm="$4" output
  if ! output="$(rpk_run topic consume "$topic" -p "$partition" -o "@${epoch}:end" -n 1 --format '%o\n' 2>"$work_dir/consume.err")"; then
    return 1
  fi
  output="$(printf '%s\n' "$output" | awk 'NF { print; exit }')"
  if [[ -z "$output" ]]; then
    printf '%s\n' "$hwm"
  elif require_uint "$output"; then
    printf '%s\n' "$output"
  else
    return 2
  fi
}

timestamp_at_offset() {
  local topic="$1" partition="$2" offset="$3" output
  if ! output="$(rpk_run topic consume "$topic" -p "$partition" -o "$offset" -n 1 --format '%d\n' 2>"$work_dir/consume.err")"; then
    return 1
  fi
  output="$(printf '%s\n' "$output" | awk 'NF { print; exit }')"
  require_uint "$output" || return 2
  printf '%s\n' "$((output / 1000))"
}

load_topic_partitions() {
  local topic="$1" output="$2"
  rpk_run topic describe "$topic" -p >"$output" 2>"$work_dir/rpk.err" || return 1
  awk '
    BEGIN { header = 0; bad = 0 }
    $1 == "PARTITION" && $4 == "REPLICAS" && $5 == "LOG-START-OFFSET" && $6 == "HIGH-WATERMARK" { header = 1; next }
    header && NF {
      if ($1 !~ /^[0-9]+$/ || $5 !~ /^[0-9]+$/ || $6 !~ /^[0-9]+$/ || seen[$1]++) { bad = 1; next }
      print $1 "\t" $5 "\t" $6
    }
    END { if (!header || bad) exit 1 }
  ' "$output" >"${output}.parsed"
  [[ -s "${output}.parsed" ]]
}

load_group_commits() {
  local topic="$1" destination="$2" list_file="$work_dir/groups.list" group output
  : >"$destination"
  rpk_run group list >"$list_file" 2>"$work_dir/rpk.err" || return 1
  awk '$1 == "BROKER" && $2 == "GROUP" && $3 == "STATE" { header=1; next }
       header && NF { if (NF < 3) exit 2; print $2 "\t" $3 }
       END { if (!header) exit 1 }' "$list_file" >"${list_file}.parsed" || return 1
  while IFS=$'\t' read -r group _; do
    [[ -n "$group" ]] || continue
    csv_contains "$IGNORE_GROUPS" "$group" && continue
    output="$work_dir/group.$(printf '%s' "$group" | tr -c 'A-Za-z0-9._-' '_')"
    rpk_run group describe "$group" -c >"$output" 2>"$work_dir/rpk.err" || return 1
    awk -v wanted="$topic" -v group="$group" '
      $1 == "TOPIC" && $2 == "PARTITION" && $3 == "CURRENT-OFFSET" { header=1; next }
      header && $1 == wanted {
        if ($2 !~ /^[0-9]+$/ || $3 !~ /^[0-9]+$/) exit 2
        print group "\t" $2 "\t" $3
      }
    ' "$output" >>"$destination" || return 1
  done <"${list_file}.parsed"
}

pg_scalar() {
  psql --no-psqlrc --tuples-only --no-align --quiet --set=ON_ERROR_STOP=1 "$@"
}

pg_window() {
  pg_scalar --command="SELECT COALESCE(EXTRACT(EPOCH FROM MIN(observed_at))::bigint, 0)::text || '|' || COALESCE(EXTRACT(EPOCH FROM MAX(observed_at))::bigint, 0)::text FROM octopus_core.wireless_frames;"
}

pg_evidence_count() {
  local topic="$1" partition="$2" first="$3" target="$4" group="$5"
  pg_scalar \
    --set=topic="$topic" --set=partition="$partition" --set=first="$first" \
    --set=target="$target" --set=group_id="$group" \
    --command="SELECT COUNT(DISTINCT record_offset) FROM octopus_core.ingestion_evidence WHERE group_id = :'group_id' AND topic = :'topic' AND partition_id = :'partition'::integer AND record_offset >= :'first'::bigint AND record_offset < :'target'::bigint AND disposition IN ('accepted', 'processed', 'duplicate');"
}

verify_trim() {
  local topic="$1" plan raw partition target lso seen=0
  plan="$work_dir/$topic.plan.tsv"
  raw="$work_dir/$topic.verify"
  declare -A desired=()
  while IFS=$'\t' read -r _ partition target; do
    desired["$partition"]="$target"
  done <"$plan"
  load_topic_partitions "$topic" "$raw" || return 1
  while IFS=$'\t' read -r partition lso _; do
    [[ -n "${desired[$partition]+present}" ]] || continue
    (( lso >= desired[$partition] )) || return 1
    seen=$((seen + 1))
  done <"${raw}.parsed"
  (( seen == ${#desired[@]} ))
}

validate_topics_file() {
  local line=0 topic days gate groups evidence extra group
  local -a configured_group_list=()
  [[ -r "$TOPICS_FILE" ]] || die "topics file is not readable: $TOPICS_FILE"
  while IFS=$'\t' read -r topic days gate groups evidence extra || [[ -n "$topic$days$gate$groups$evidence$extra" ]]; do
    line=$((line + 1))
    [[ -z "$topic" || "$topic" == \#* ]] && continue
    [[ -z "$extra" ]] || die "$TOPICS_FILE:$line has too many columns"
    [[ "$topic" =~ ^[A-Za-z0-9._-]+$ ]] || die "$TOPICS_FILE:$line has invalid topic"
    if ! require_uint "$days" || (( days < 1 )); then
      die "$TOPICS_FILE:$line keep_days must be >= 1"
    fi
    [[ "$gate" == "none" || "$gate" == "pg" ]] || die "$TOPICS_FILE:$line has invalid gate"
    [[ -n "$groups" && "$groups" != "-" ]] || die "$TOPICS_FILE:$line requires at least one consumer group"
    IFS=',' read -r -a configured_group_list <<<"$groups"
    for group in "${configured_group_list[@]}"; do
      [[ "$group" =~ ^[A-Za-z0-9._-]+$ ]] || die "$TOPICS_FILE:$line has an invalid consumer group"
    done
    if [[ "$gate" == "pg" ]]; then
      [[ -n "$evidence" && "$evidence" != "-" ]] || die "$TOPICS_FILE:$line requires an evidence group"
      [[ "$evidence" =~ ^[A-Za-z0-9._-]+$ ]] || die "$TOPICS_FILE:$line has an invalid evidence group"
      [[ "$topic" == "wireless.audit" ]] || die "$TOPICS_FILE:$line pg gate is only defined for wireless.audit"
    fi
    topic_is_active "$topic" && selected_topics+=("$topic")
  done <"$TOPICS_FILE"
  ((${#selected_topics[@]} > 0)) || die "ACTIVE_TOPICS selected no configured topics"
}

plan_topic() {
  local topic="$1" keep_days="$2" gate="$3" required_groups_csv="$4" evidence_group="$5"
  local raw commits plan
  local cutoff_epoch pg_floor=0 pg_newest=0 pg_data partition lso hwm cutoff group commit
  local min_commit holder target delete total=0 trim=0 fraction expected persisted first_epoch coverage_start
  local -a required=()
  declare -A commit_by_group_partition=()
  declare -A discovered_groups=()

  raw="$work_dir/$topic.partitions"
  commits="$work_dir/$topic.commits"
  plan="$work_dir/$topic.plan.tsv"

  topic_status[$topic]="$STATUS_OK"
  topic_trim_records[$topic]=0
  topic_records[$topic]=0
  : >"$plan"
  cutoff_epoch="$((started_at - keep_days * 86400))"

  if ! load_topic_partitions "$topic" "$raw"; then
    mark_failed "$topic" "$STATUS_PARSE_ERROR" "topic partition output"
    return
  fi
  if ! load_group_commits "$topic" "$commits"; then
    mark_failed "$topic" "$STATUS_PARSE_ERROR" "consumer group output"
    return
  fi
  while IFS=$'\t' read -r group partition commit; do
    [[ -n "$group" ]] || continue
    if [[ -n "${commit_by_group_partition[$group:$partition]+present}" ]]; then
      mark_failed "$topic" "$STATUS_PARSE_ERROR" "duplicate commit for $group partition $partition"
      return
    fi
    commit_by_group_partition["$group:$partition"]="$commit"
    discovered_groups["$group"]=1
  done <"$commits"
  IFS=',' read -r -a required <<<"$required_groups_csv"
  for group in "${required[@]}"; do
    if [[ -z "${discovered_groups[$group]:-}" ]]; then
      mark_failed "$topic" "$STATUS_GROUP_BLOCKED" "required group $group has no commits for topic"
      return
    fi
  done

  if [[ "$gate" == "pg" ]]; then
    if ! pg_data="$(pg_window)"; then
      mark_failed "$topic" "$STATUS_GATE_COVERAGE" "PostgreSQL gate query failed"
      return
    fi
    IFS='|' read -r pg_floor pg_newest <<<"$pg_data"
    if ! require_uint "$pg_floor" || ! require_uint "$pg_newest" || (( pg_floor == 0 || pg_newest == 0 )); then
      mark_failed "$topic" "$STATUS_GATE_COVERAGE" "PostgreSQL projection is empty or unparsable"
      return
    fi
    if (( started_at - pg_newest > PG_MAX_STALE_MIN * 60 )); then
      mark_failed "$topic" "$STATUS_GATE_STALE" "newest projected row exceeds PG_MAX_STALE_MIN"
      return
    fi
  fi

  printf '%-24s %5s %12s %12s %12s %-32s %12s %12s\n' TOPIC PART LSO HWM CUTOFF HOLDER MIN_COMMIT TARGET
  while IFS=$'\t' read -r partition lso hwm; do
    total=$((total + hwm - lso))
    if ! cutoff="$(offset_at_epoch "$topic" "$partition" "$cutoff_epoch" "$hwm")"; then
      mark_failed "$topic" "$STATUS_CONSUME_ERROR" "cannot resolve cutoff for partition $partition"
      return
    fi
    if (( cutoff < lso || cutoff > hwm )); then
      mark_failed "$topic" "$STATUS_PARSE_ERROR" "cutoff is outside partition $partition bounds"
      return
    fi
    min_commit=-1
    holder=""
    for group in "${!discovered_groups[@]}"; do
      commit="${commit_by_group_partition[$group:$partition]:-}"
      if [[ -z "$commit" ]]; then
        mark_failed "$topic" "$STATUS_GROUP_BLOCKED" "group $group has no commit for partition $partition"
        return
      fi
      if (( commit > hwm )); then
        mark_failed "$topic" "$STATUS_PARSE_ERROR" "group $group commit exceeds partition $partition HWM"
        return
      fi
      if (( min_commit < 0 || commit < min_commit )); then
        min_commit="$commit"
        holder="$group"
      fi
    done
    (( min_commit >= 0 )) || { mark_failed "$topic" "$STATUS_GROUP_BLOCKED" "no consumer commits"; return; }
    target="$cutoff"
    (( min_commit < target )) && target="$min_commit"
    (( target < lso )) && target="$lso"
    (( target > hwm )) && { mark_failed "$topic" "$STATUS_PARSE_ERROR" "target exceeds HWM"; return; }

    if [[ "$gate" == "pg" && "$target" -gt "$lso" ]]; then
      if ! first_epoch="$(timestamp_at_offset "$topic" "$partition" "$lso")"; then
        mark_failed "$topic" "$STATUS_CONSUME_ERROR" "cannot read LSO timestamp for partition $partition"
        return
      fi
      coverage_start="$lso"
      if (( first_epoch < pg_floor )); then
        if [[ -z "$ALLOW_UNPROJECTED_BEFORE_EPOCH" ]] || ! require_uint "$ALLOW_UNPROJECTED_BEFORE_EPOCH" || (( ALLOW_UNPROJECTED_BEFORE_EPOCH < pg_floor - 60 || ALLOW_UNPROJECTED_BEFORE_EPOCH > pg_floor + 60 )); then
          mark_failed "$topic" "$STATUS_GATE_FLOOR" "partition $partition begins before PostgreSQL floor"
          return
        fi
        if ! coverage_start="$(offset_at_epoch "$topic" "$partition" "$ALLOW_UNPROJECTED_BEFORE_EPOCH" "$hwm")"; then
          mark_failed "$topic" "$STATUS_CONSUME_ERROR" "cannot resolve floor override for partition $partition"
          return
        fi
        (( coverage_start < lso )) && coverage_start="$lso"
      fi
      if (( coverage_start < target )); then
        expected=$((target - coverage_start))
        if ! persisted="$(pg_evidence_count "$topic" "$partition" "$coverage_start" "$target" "$evidence_group")" || ! require_uint "$persisted"; then
          mark_failed "$topic" "$STATUS_GATE_COVERAGE" "evidence query failed for partition $partition"
          return
        fi
        if (( persisted != expected )); then
          mark_failed "$topic" "$STATUS_GATE_COVERAGE" "partition $partition has $persisted/$expected persisted offsets"
          return
        fi
      fi
    fi

    delete=$((target - lso))
    trim=$((trim + delete))
    printf '%-24s %5s %12s %12s %12s %-32s %12s %12s\n' "$topic" "$partition" "$lso" "$hwm" "$cutoff" "$holder" "$min_commit" "$target"
    printf '%s\t%s\t%s\n' "$topic" "$partition" "$target" >>"$plan"
  done <"${raw}.parsed"

  topic_records[$topic]="$total"
  topic_trim_records[$topic]="$trim"
  fraction="$(awk -v trim="$trim" -v total="$total" 'BEGIN { if (total == 0) print "0"; else printf "%.8f", trim / total }')"
  if awk -v fraction="$fraction" -v maximum="$MAX_TRIM_FRACTION" 'BEGIN { exit !(fraction > maximum) }'; then
    mark_failed "$topic" "$STATUS_BREAKER" "trim fraction $fraction exceeds $MAX_TRIM_FRACTION"
    return
  fi
  if (( trim == 0 )); then
    topic_status[$topic]="$STATUS_NOTHING"
  fi
}

main() {
  local topic days gate groups evidence extra
  for command in bash curl date psql rpk timeout; do command -v "$command" >/dev/null || die "missing command: $command"; done
  case "$DRY_RUN" in
    true|TRUE|1|yes|YES|false|FALSE|0|no|NO) ;;
    *) die "invalid boolean: $DRY_RUN" ;;
  esac
  [[ "$MAX_TRIM_FRACTION" =~ ^0(\.[0-9]+)?$|^1(\.0+)?$ ]] || die "MAX_TRIM_FRACTION must be between 0 and 1"
  require_uint "$PG_MAX_STALE_MIN" || die "PG_MAX_STALE_MIN must be an integer"
  validate_topics_file

  while IFS=$'\t' read -r topic days gate groups evidence extra || [[ -n "$topic$days$gate$groups$evidence$extra" ]]; do
    [[ -z "$topic" || "$topic" == \#* ]] && continue
    topic_is_active "$topic" || continue
    plan_topic "$topic" "$days" "$gate" "$groups" "$evidence"
  done <"$TOPICS_FILE"

  if (( failed_topics > 0 )); then
    log "planning failed for $failed_topics topic(s); no trim commands were run" >&2
    return 1
  fi
  if is_true "$DRY_RUN"; then
    run_success=1
    log "dry-run complete; no trim commands were run"
    return 0
  fi
  for topic in "${selected_topics[@]}"; do
    [[ "${topic_status[$topic]}" == "$STATUS_NOTHING" ]] && continue
    if ! rpk_run topic trim-prefix --from-file "$work_dir/$topic.plan.tsv" --no-confirm; then
      mark_failed "$topic" "$STATUS_TRIM_ERROR" "rpk trim-prefix failed"
      return 1
    fi
    if ! verify_trim "$topic"; then
      mark_failed "$topic" "$STATUS_TRIM_ERROR" "post-trim LSO verification failed"
      return 1
    fi
  done
  run_success=1
  log "trim complete"
}

main "$@"
