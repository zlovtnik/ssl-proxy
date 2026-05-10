<script>
  import AdminResourcePage from "./AdminResourcePage.svelte"
  import { formatTime } from "../lib/format"

  export let initial = {}

  const config = {
    title: "MAC Identifiers",
    newLabel: "New MAC identifier",
    newTitle: "New MAC Identifier",
    editTitle: "Edit MAC Identifier",
    submitLabel: "Save identifier",
    deleteConfirm: "Remove",
    savedMessage: "MAC identifier saved.",
    deletedMessage: "MAC identifier removed.",
    paramKey: "device",
    defaultSort: "display_name",
    defaultDirection: "asc",
    search: true,
    searchPlaceholder: "Search MAC, device, owner, hostname, OS",
    emptyRecord: { display_name: "", username: "", hostname: "", os_hint: "", mac_hint: "", notes: "" },
    columns: [
      { key: "display_name", label: "Device", sortable: true, size: "md" },
      { key: "username", label: "Owner", sortable: true, size: "md" },
      { key: "mac_hint", label: "MAC", sortable: true, size: "md" },
      { key: "hostname", label: "Hostname", sortable: true, size: "md" },
      { key: "os_hint", label: "OS", sortable: true, size: "sm" },
      { key: "last_seen", label: "Last Occurred", shortLabel: "Last Seen", sortable: true, size: "md", format: formatTime, filterType: "date" }
    ],
    fields: [
      { key: "display_name", label: "Device", placeholder: "Lobby printer" },
      { key: "username", label: "Owner", placeholder: "jane.doe" },
      { key: "mac_hint", label: "MAC", placeholder: "10:20:30:40:50:60" },
      { key: "hostname", label: "Hostname", placeholder: "printer-lobby" },
      { key: "os_hint", label: "OS", placeholder: "iOS, macOS, printer" },
      { key: "notes", label: "Notes", type: "textarea" }
    ]
  }
</script>

<AdminResourcePage {initial} {config} />
