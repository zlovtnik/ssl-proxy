# AuditLog Model Refactoring Summary

## Changes Made

### Step 1: Deleted Dead Code [done]
- **Deleted**: `app/models/wireless_audit_identity.rb`
- **Deleted**: `test/models/wireless_audit_identity_test.rb`
- **Reason**: Both `WirelessAuditIdentity` and `WirelessDeviceInventory` pointed to the same view (`v_wireless_device_inventory`). Only `WirelessDeviceInventory` was actually used by `IdentitiesController`. The only difference was a slightly different search scope.

### Step 2: Extracted AuditLogPresenter [done]
- **Created**: `app/presenters/audit_log_presenter.rb`
- **Moved display logic from AuditLog model**:
  - `security_labels` - Decodes security_flags bitmask into human-readable labels
  - `compact_security_label` - Joins security labels with commas
  - `frame_flags_label` - Formats frame control flags as readable text
  - `protocol_summary` - Combines protocol layers into summary string
  - `raw_frame_bytes` - Decodes base64 raw frame data
  - `raw_frame_hex_dump` - Formats raw frame as hex dump display

- **Updated**: `app/controllers/audit_logs_controller.rb`
  - `show` action now wraps entry in `AuditLogPresenter`
  - `live_payload` method uses presenter for display methods
  - Fixed `retry` reference (was `retry_flag` in model, now just `retry`)

### Step 3: Documented Promoted vs Payload-Only Columns [done]
- **Updated**: `app/models/audit_log.rb`
- **Added explicit column lists**:
  - `PROMOTED_COLUMNS` - 70+ columns that exist as real table columns
  - `PAYLOAD_ONLY_FIELDS` - Fields still stored only in the jsonb payload
  
- **Simplified `payload_value` method**:
  - Reads promoted columns directly if key is in PROMOTED_COLUMNS
  - Falls back to reading from payload for any non-promoted key
  - No more ambiguous COALESCE pattern

- **Removed display methods** from model (moved to presenter)

## Benefits

1. **Clearer separation of concerns**
   - Model = data access only
   - Presenter = display/formatting logic
   - Controller = orchestration

2. **Explicit about data location**
   - No more guessing if a field is promoted or in payload
   - `PROMOTED_COLUMNS` and `PAYLOAD_ONLY_FIELDS` document the schema
   - Future column promotions are obvious (move from one list to the other)

3. **Easier to test**
   - Display logic can be tested independently via presenter
   - Model tests focus on data access and scopes
   - No mixing of concerns

4. **Removed dead code**
   - One less model to maintain
   - No confusion about which identity model to use

## What's Left (Future Work)

### Step 4: Replace FilterBar with QueryBuilder
- `app/javascript/components/FilterBar.svelte` is only used by audit logs page
- Every other page uses `QueryBuilder` + `CommandPaletteSearch`
- Would make audit log filtering consistent with rest of app

### Step 5: Consolidate Live Updates
- Audit log page has both polling (`setInterval`) AND ActionCable
- Deduplication works but adds complexity
- Should pick one path (probably ActionCable if reliable)

## Files Changed

```text
Deleted:
  app/models/wireless_audit_identity.rb
  test/models/wireless_audit_identity_test.rb

Created:
  app/presenters/audit_log_presenter.rb

Modified:
  app/models/audit_log.rb
  app/controllers/audit_logs_controller.rb
```

## Testing Notes

- Syntax validation passed for all modified files
- Test helper (`test/support/sync_ingest_helpers.rb`) already handles promoted columns correctly
- Database tests require running database (not available during refactor)
- Manual testing recommended:
  - Visit `/audit_logs` - verify list page works
  - Visit `/audit_logs/:id` - verify detail page shows all fields
  - Check live updates work
  - Verify CSV export includes all expected columns
