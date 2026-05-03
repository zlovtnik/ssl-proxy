-- Add probe_fingerprint and vendor_name columns to sync_scan_ingest table
-- for T3 OUI vendor lookup and probe request fingerprinting

ALTER TABLE sync_scan_ingest
  ADD COLUMN IF NOT EXISTS probe_fingerprint TEXT,
  ADD COLUMN IF NOT EXISTS vendor_name TEXT;

CREATE INDEX IF NOT EXISTS idx_sync_scan_ingest_probe_fingerprint 
  ON sync_scan_ingest(probe_fingerprint) 
  WHERE probe_fingerprint IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_sync_scan_ingest_vendor_name 
  ON sync_scan_ingest(vendor_name) 
  WHERE vendor_name IS NOT NULL;

COMMENT ON COLUMN sync_scan_ingest.probe_fingerprint IS 
  'FNV-1a hash of IE sequence for probe request frames (subtype 4)';

COMMENT ON COLUMN sync_scan_ingest.vendor_name IS 
  'Vendor name from OUI lookup of BSSID or source MAC address';
