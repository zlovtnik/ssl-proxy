-- object: vec_install_cron_jobs
-- folder: cron
-- depends_on: all vec_* objects and materialized views
create or replace function vec_refresh_device_repetition_score()
returns void
language plpgsql
as $$
begin
  if not vec_try_begin_maintenance_job('vec-refresh-device-repetition-score') then
    return;
  end if;

  refresh materialized view concurrently v_device_repetition_score;

  perform vec_finish_maintenance_job('vec-refresh-device-repetition-score');
exception when others then
  perform vec_finish_maintenance_job('vec-refresh-device-repetition-score');
  raise;
end;
$$;

create or replace function vec_refresh_ap_risk_score()
returns void
language plpgsql
as $$
begin
  if not vec_try_begin_maintenance_job('vec-refresh-ap-risk-score') then
    return;
  end if;

  refresh materialized view concurrently mv_ap_risk_score;
  perform check_high_risk_aps();

  perform vec_finish_maintenance_job('vec-refresh-ap-risk-score');
exception when others then
  perform vec_finish_maintenance_job('vec-refresh-ap-risk-score');
  raise;
end;
$$;

create or replace function vec_install_cron_jobs()
returns void
language plpgsql
as $$
begin
  if to_regnamespace('cron') is null then
    raise exception 'pg_cron schema is unavailable';
  end if;

  perform cron.schedule(
    'vec-build-behaviour-snapshots',
    '0,10,20,30,40,50 * * * *',
    $cron$select vec_run_maintenance_sql('vec-build-behaviour-snapshots', $$select vec_build_behaviour_snapshots()$$);$cron$
  );

  perform cron.schedule(
    'vec-build-frame-sequences',
    '2,12,22,32,42,52 * * * *',
    $cron$select vec_run_maintenance_sql('vec-build-frame-sequences', $$select vec_build_frame_sequences()$$);$cron$
  );

  perform cron.schedule(
    'vec-build-timing-profiles',
    '4,19,34,49 * * * *',
    $cron$select vec_run_maintenance_sql('vec-build-timing-profiles', $$select vec_build_timing_profiles()$$);$cron$
  );

  perform cron.schedule(
    'vec-build-baseline-profiles',
    '6,21,36,51 * * * *',
    $cron$select vec_run_maintenance_sql('vec-build-baseline-profiles', $$select vec_build_baseline_profiles()$$);$cron$
  );

  perform cron.schedule(
    'vec-build-infrastructure-graph',
    '8,23,38,53 * * * *',
    $cron$select vec_run_maintenance_sql('vec-build-infrastructure-graph', $$select vec_build_infrastructure_graph()$$);$cron$
  );

  perform cron.schedule(
    'vec-detect-rogue-clusters',
    '10,25,40,55 * * * *',
    $cron$select vec_run_maintenance_sql('vec-detect-rogue-clusters', $$select vec_detect_rogue_clusters()$$);$cron$
  );

  perform cron.schedule(
    'vec-enqueue-embedding-jobs',
    '*/5 * * * *',
    $cron$select vec_run_maintenance_sql('vec-enqueue-embedding-jobs', $$select vec_enqueue_embedding_jobs()$$);$cron$
  );

  perform cron.schedule(
    'vec-materialize-similarity-pairs',
    '12,27,42,57 * * * *',
    $cron$select vec_run_maintenance_sql('vec-materialize-similarity-pairs', $$select vec_materialize_similarity_pairs('nomic-embed-text-v2-moe'::text, 10::integer, 0.05::double precision, 0.88::double precision, 0.10::double precision, 0.05::double precision)$$);$cron$
  );

  perform cron.schedule(
    'vec-apply-similarity-flags',
    '14,29,44,59 * * * *',
    $cron$select vec_run_maintenance_sql('vec-apply-similarity-flags', $$select vec_apply_similarity_flags('nomic-embed-text-v2-moe'::text, 0.05::double precision, 0.88::double precision)$$);$cron$
  );

  perform cron.schedule(
    'vec-fuse-device-identities',
    '5,20,35,50 * * * *',
    $cron$select vec_run_maintenance_sql('vec-fuse-device-identities', $$select vec_fuse_device_identities()$$);$cron$
  );

  perform cron.schedule(
    'vec-refresh-device-repetition-score',
    '3,18,33,48 * * * *',
    $cron$select vec_refresh_device_repetition_score();$cron$
  );

  perform cron.schedule(
    'vec-release-expired-leases',
    '* * * * *',
    $cron$select vec_release_expired_leases();$cron$
  );

  perform cron.schedule(
    'vec-reap-stale-workers',
    '*/5 * * * *',
    $cron$select vec_reap_stale_workers();$cron$
  );

  perform cron.schedule(
    'vec-update-transition-model',
    '7,22,37,52 * * * *',
    $cron$select vec_run_maintenance_sql('vec-update-transition-model', $$select vec_update_transition_model()$$);$cron$
  );

  perform cron.schedule(
    'vec-update-device-centroids',
    '10,25,40,55 * * * *',
    $cron$select vec_run_maintenance_sql('vec-update-device-centroids', $$select vec_update_device_centroids()$$);$cron$
  );

  perform cron.schedule(
    'vec-refresh-ap-risk-score',
    '9,24,39,54 * * * *',
    $cron$select vec_refresh_ap_risk_score();$cron$
  );
end;
$$;

do $$
begin
  if exists (select 1 from pg_extension where extname = 'pg_cron') then
    perform vec_install_cron_jobs();
  else
    raise notice 'pg_cron extension unavailable; skipping vec cron job installation';
  end if;
end $$;
