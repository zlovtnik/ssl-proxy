export type Verdict =
  | 'BLOCKED'
  | 'PERSISTENT_RECONNECT'
  | 'AGGRESSIVE_POLLING'
  | 'HEURISTIC_FLAG_DATA_EXFIL'
  | 'TARPIT';

export interface HostSnapshot {
  host: string;
  blocked_attempts: number;
  blocked_bytes_approx: number;
  frequency_hz: number;
  risk_score: number;
  verdict: Verdict;
  tarpit_held_ms: number;
  battery_saved_mwh: number;
  category: string;
  consecutive_blocks: number;
  iat_ms?: number;
  tls_ver?: string;
  alpn?: string;
  cipher_suites_count?: number;
  ja3_lite?: string;
  resolved_ip?: string;
  asn_org?: string;
  last_reason?: string;
}

export interface LiveStats {
  active_tunnels: number;
  tunnels_opened: number;
  up_kBps: number;
  down_kBps: number;
  bytes_up: number;
  bytes_down: number;
  blocked: number;
  obfuscated: number;
}

export interface PeerSummary {
  wg_pubkey: string;
  peer_ip?: string;
  peer_hostname?: string;
  display_name?: string;
  username?: string;
  active_device_id?: string;
  last_handshake_at?: string;
  bytes_up: number;
  bytes_down: number;
  blocked_bytes_approx: number;
  allowed_bytes: number;
  blocked_count: number;
  allowed_count: number;
  sessions_active: number;
}

export interface BandwidthPoint {
  bucket: string;
  wg_pubkey: string;
  device_id?: string;
  display_name?: string;
  username?: string;
  bytes_up_delta: number;
  bytes_down_delta: number;
  blocked_bytes_delta: number;
  allowed_bytes_delta: number;
  blocked_count_delta: number;
  allowed_count_delta: number;
  sessions_active: number;
  blocked_bytes_is_approx: boolean;
}

export interface StatsSummary {
  total_hosts: number;
  tarpit_count: number;
  top_category?: string;
  highest_risk_host?: string;
}

export interface DeviceInfo {
  device_id: string;
  wg_pubkey?: string;
  claim_token_hash?: string;
  display_name?: string;
  username?: string;
  hostname?: string;
  os_hint?: string;
  mac_hint?: string;
  first_seen: string;
  last_seen: string;
  notes?: string;
}

export interface DeviceUpsertRequest {
  device_id?: string;
  wg_pubkey?: string;
  display_name?: string;
  username?: string;
  hostname?: string;
  os_hint?: string;
  mac_hint?: string;
  notes?: string;
  regenerate_claim_token?: boolean;
}

export interface DeviceUpsertResponse {
  device_id: string;
  claim_token?: string;
  device: DeviceInfo;
}

export interface ClaimResponse {
  device_id: string;
  wg_pubkey: string;
  peer_ip: string;
  claimed_at: string;
  expires_at: string;
}

export interface HealthStatus {
  status: string;
  [key: string]: unknown;
}

export interface SyncPublisherHealth {
  configured: boolean;
  auth_enabled: boolean;
  tls_enabled: boolean;
  inline_payload_max_bytes: number;
  outbox_dir: string;
  last_attempt_at?: string;
  last_publish_at?: string;
  last_error?: string;
}

export interface SyncSubjectCount {
  subject: string;
  count: number;
}

export interface SyncStatusReport {
  status: string;
  publisher: SyncPublisherHealth;
  published_subjects: SyncSubjectCount[];
  last_error?: string;
}

export interface DashboardEvent {
  type: string;
  host: string;
  time: string;
  verdict?: string;
  reason?: string;
  metrics?: {
    attempt_count?: number;
    frequency_hz?: number;
  };
  fingerprint?: {
    tls_ver?: string;
    alpn?: string;
  };
  [key: string]: unknown;
}

export type WsConnectionStatus = 'connected' | 'connecting' | 'disconnected' | 'error';
