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
      { key: "enabled", label: "Enabled", sortable: true, width: "w-20", format: (value) => displayBoolean(value, "yes") || "no" },
      { key: "location_id", label: "Location", sortable: true, width: "w-28", format: (value) => value || "any" },
      { key: "ssid", label: "SSID", sortable: true, width: "w-32", format: (value) => value || "any" },
      { key: "bssid", label: "BSSID", sortable: true, width: "w-36", format: (value) => value || "any" },
      { key: "label", label: "Label", sortable: true, width: "w-36" },
      { key: "updated_at", label: "Updated", sortable: true, width: "w-36", format: formatTime }
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
