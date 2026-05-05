import MacChip from "../components/MacChip.svelte"
import { displayBoolean, formatTime, shortFingerprint } from "../lib/format"

/**
 * @typedef {Object} ColumnDefinition
 * @property {string} key - Column key matching row data
 * @property {string} label - Display label
 * @property {boolean} [sortable] - Enable sorting
 * @property {string} [minWidth] - Minimum width (Tailwind class)
 * @property {Function} [href] - Generate link URL from row
 * @property {Function} [format] - Format cell value
 * @property {string} [filterType] - Filter type (date, number, boolean, text)
 * @property {*} [component] - Svelte component for cell
 * @property {Function} [componentProps] - Generate component props from row
 * @property {string} [hiddenBelow] - Hide column below breakpoint (sm, md, lg)
 */

/**
 * Build column definitions for audit log table
 * @param {Object} options
 * @param {Object} options.endpoints - API endpoints
 * @param {Object} options.macOptions - MAC address display options
 * @param {boolean} options.fullMacs - Show full MAC addresses
 * @returns {ColumnDefinition[]}
 */
export function buildAuditLogColumns({ endpoints = {}, macOptions = {}, fullMacs = false }) {
  const macProps = (value, display) => ({
    mac: value,
    display,
    masked: !fullMacs,
    auditLogsUrl: macOptions.auditLogsUrl || endpoints.index || "/audit_logs",
    identitiesUrl: macOptions.identitiesUrl || "/identities",
    shadowItUrl: macOptions.shadowItUrl || "/shadow_it_alerts",
    inventoryUrl: macOptions.inventoryUrl || "/identities/inventory.json",
    summaryUrl: macOptions.macSummaryUrl || "/identities/mac_summary.json",
    recentAuditLogsUrl: macOptions.recentAuditLogsUrl || "/audit_logs/recent.json"
  })

  return [
    {
      key: "observed_at",
      label: "Observed",
      sortable: true,
      minWidth: "min-w-32",
      href: (row) => row.show_url,
      format: formatTime,
      filterType: "date"
    },
    {
      key: "sensor_id",
      label: "Sensor",
      sortable: true,
      minWidth: "min-w-24"
    },
    {
      key: "location_id",
      label: "Location",
      sortable: true,
      minWidth: "min-w-20"
    },
    {
      key: "frame_subtype",
      label: "Subtype",
      sortable: true,
      minWidth: "min-w-24",
      format: (value, row) => value || row.event_type || "event"
    },
    {
      key: "ssid",
      label: "SSID",
      sortable: true,
      minWidth: "min-w-28"
    },
    {
      key: "source_mac",
      label: "Source",
      sortable: true,
      minWidth: "min-w-32",
      component: MacChip,
      componentProps: (value, row) => macProps(value, row.source_mac_display)
    },
    {
      key: "destination_bssid",
      label: "Dest BSSID",
      description: "Destination BSSID",
      sortable: true,
      minWidth: "min-w-32",
      component: MacChip,
      componentProps: (value, row) => macProps(value, row.destination_bssid_display)
    },
    {
      key: "signal_dbm",
      label: "Signal",
      sortable: true,
      minWidth: "min-w-16",
      filterType: "number"
    },
    {
      key: "raw_len",
      label: "Bytes",
      sortable: true,
      minWidth: "min-w-16",
      filterType: "number"
    },
    {
      key: "frame_control_flags",
      label: "Flags",
      sortable: true,
      minWidth: "min-w-28",
      hiddenBelow: "lg",
      format: (value, row) => row.frame_flags_label || value || "",
      filterType: "number"
    },
    {
      key: "security_flags",
      label: "Security",
      sortable: true,
      minWidth: "min-w-28",
      hiddenBelow: "md",
      format: (value, row) => row.security_label || row.security_flags || "open/unknown",
      filterType: "number"
    },
    {
      key: "vendor_name",
      label: "Vendor",
      sortable: true,
      minWidth: "min-w-32",
      hiddenBelow: "md"
    },
    {
      key: "device_fingerprint",
      label: "Fingerprint",
      shortLabel: "Device FP",
      sortable: true,
      minWidth: "min-w-28",
      hiddenBelow: "lg",
      format: shortFingerprint
    },
    {
      key: "probe_fingerprint",
      label: "Probe FP",
      sortable: true,
      minWidth: "min-w-28",
      hiddenBelow: "lg",
      format: shortFingerprint
    },
    {
      key: "wps_device_name",
      label: "WPS Device",
      shortLabel: "WPS Dev",
      sortable: true,
      minWidth: "min-w-32",
      hiddenBelow: "lg"
    },
    {
      key: "wps_manufacturer",
      label: "WPS Mfr",
      sortable: true,
      minWidth: "min-w-28",
      hiddenBelow: "lg"
    },
    {
      key: "wps_model_name",
      label: "WPS Model",
      sortable: true,
      minWidth: "min-w-28",
      hiddenBelow: "lg"
    },
    {
      key: "more_data",
      label: "More Data",
      shortLabel: "More",
      sortable: true,
      minWidth: "min-w-20",
      hiddenBelow: "lg",
      format: (value) => displayBoolean(value, "yes"),
      filterType: "boolean"
    },
    {
      key: "retry",
      label: "Retry",
      sortable: true,
      minWidth: "min-w-16",
      hiddenBelow: "lg",
      format: (value) => displayBoolean(value, "yes"),
      filterType: "boolean"
    },
    {
      key: "power_save",
      label: "Pwr Save",
      description: "Power Save",
      sortable: true,
      minWidth: "min-w-20",
      hiddenBelow: "lg",
      format: (value) => displayBoolean(value, "yes"),
      filterType: "boolean"
    },
    {
      key: "protected",
      label: "Protected",
      sortable: true,
      minWidth: "min-w-20",
      hiddenBelow: "lg",
      format: (value) => displayBoolean(value, "yes"),
      filterType: "boolean"
    },
    {
      key: "handshake_captured",
      label: "Handshake",
      shortLabel: "HS",
      sortable: true,
      minWidth: "min-w-20",
      hiddenBelow: "lg",
      format: (value) => displayBoolean(value),
      filterType: "boolean"
    },
    {
      key: "tags",
      label: "Threats",
      sortable: false,
      minWidth: "min-w-40",
      hiddenBelow: "md",
      format: (value) => Array.isArray(value) ? value.join(", ") : ""
    }
  ]
}
