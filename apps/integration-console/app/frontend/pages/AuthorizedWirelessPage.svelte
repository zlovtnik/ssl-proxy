<script>
  import AdminResourcePage from "./AdminResourcePage.svelte"
  import { displayBoolean, formatTime } from "../lib/format"

  export let initial = {}

  const config = {
    title: "Authorized Wireless",
    newLabel: "New authorized network",
    newTitle: "New Authorized Wireless",
    editTitle: "Edit Authorized Wireless",
    submitLabel: "Save network",
    deleteConfirm: "Remove",
    savedMessage: "Authorized wireless network saved.",
    deletedMessage: "Authorized wireless network removed.",
    paramKey: "authorized_wireless_network",
    defaultSort: "ssid",
    defaultDirection: "asc",
    emptyRecord: { enabled: true, ssid: "", bssid: "", location_id: "", label: "", notes: "" },
    columns: [
      { key: "enabled", label: "Enabled", sortable: true, size: "sm", format: (value) => displayBoolean(value, "yes") || "no", filterType: "boolean" },
      { key: "location_id", label: "Location", sortable: true, size: "sm", format: (value) => value || "any" },
      { key: "ssid", label: "SSID", sortable: true, size: "md", format: (value) => value || "any" },
      { key: "bssid", label: "BSSID", sortable: true, size: "md", format: (value) => value || "any" },
      { key: "label", label: "Label", sortable: true, size: "md" },
      { key: "updated_at", label: "Updated", sortable: true, size: "md", format: formatTime, filterType: "date" }
    ],
    fields: [
      { key: "ssid", label: "SSID", placeholder: "CorpWiFi" },
      { key: "bssid", label: "BSSID", placeholder: "10:20:30:40:50:60" },
      { key: "location_id", label: "Location", placeholder: "optional" },
      { key: "label", label: "Label", placeholder: "Lobby AP" },
      { key: "enabled", label: "Enabled", type: "checkbox" },
      { key: "notes", label: "Notes", type: "textarea" }
    ]
  }
</script>

<AdminResourcePage {initial} {config} />
