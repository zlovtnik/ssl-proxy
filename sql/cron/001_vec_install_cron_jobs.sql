-- object: vec_install_cron_jobs
-- folder: cron
-- depends_on: all vec_* objects and materialized views
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
    '*/5 * * * *',
    $cron$select vec_build_behaviour_snapshots();$cron$
  );

  perform cron.schedule(
    'vec-build-frame-sequences',
    '*/5 * * * *',
    $cron$select vec_build_frame_sequences();$cron$
  );

  perform cron.schedule(
    'vec-build-baseline-profiles',
    '*/15 * * * *',
    $cron$select vec_build_baseline_profiles();$cron$
  );

  perform cron.schedule(
    'vec-build-infrastructure-graph',
    '*/5 * * * *',
    $cron$select vec_build_infrastructure_graph();$cron$
  );

  perform cron.schedule(
    'vec-detect-rogue-clusters',
    '*/5 * * * *',
    $cron$select vec_detect_rogue_clusters();$cron$
  );

  perform cron.schedule(
    'vec-enqueue-embedding-jobs',
    '*/2 * * * *',
    $cron$select vec_enqueue_embedding_jobs();$cron$
  );

  perform cron.schedule(
    'vec-materialize-similarity-pairs',
    '*/5 * * * *',
    $cron$select vec_materialize_similarity_pairs('nomic-embed-text-v2-moe'::text, 10::integer, 0.05::double precision, 0.92::double precision, 0.10::double precision);$cron$
  );

  perform cron.schedule(
    'vec-refresh-device-repetition-score',
    '*/5 * * * *',
    $cron$REFRESH MATERIALIZED VIEW CONCURRENTLY v_device_repetition_score;$cron$
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
    '*/15 * * * *',
    $cron$select vec_update_transition_model();$cron$
  );

  perform cron.schedule(
    'vec-refresh-ap-risk-score',
    '*/5 * * * *',
    $cron$REFRESH MATERIALIZED VIEW CONCURRENTLY mv_ap_risk_score; SELECT check_high_risk_aps();$cron$
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
