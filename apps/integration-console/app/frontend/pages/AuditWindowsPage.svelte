<script>
  import AdminResourcePage from "./AdminResourcePage.svelte"
  import { displayBoolean } from "../lib/format"

  export let initial = {}

  const config = {
    title: "Audit Windows",
    newLabel: "New audit window",
    newTitle: "New Audit Window",
    editTitle: "Edit Audit Window",
    submitLabel: "Save window",
    deleteConfirm: "Remove",
    savedMessage: "Audit window saved and published.",
    deletedMessage: "Audit window removed.",
    paramKey: "audit_window",
    defaultSort: "location_id",
    defaultDirection: "asc",
    emptyRecord: { enabled: true, location_id: "", timezone: "America/New_York", days: "", start_time: "", end_time: "" },
    columns: [
      { key: "location_id", label: "Location", sortable: true, size: "md" },
      { key: "timezone", label: "Timezone", sortable: true, size: "md" },
      { key: "days", label: "Days", sortable: true, size: "md" },
      { key: "start_time", label: "Start", sortable: true, size: "sm" },
      { key: "end_time", label: "End", sortable: true, size: "sm" },
      { key: "enabled", label: "Enabled", sortable: true, size: "sm", format: (value) => displayBoolean(value, "yes") || "no", filterType: "boolean" }
    ],
    fields: [
      { key: "location_id", label: "Location", placeholder: "lab" },
      { key: "timezone", label: "Timezone", placeholder: "America/New_York" },
      { key: "days", label: "Days", placeholder: "mon,tue,wed,thu,fri" },
      { key: "start_time", label: "Start", type: "time" },
      { key: "end_time", label: "End", type: "time" },
      { key: "enabled", label: "Enabled", type: "checkbox" }
    ]
  }
</script>

<AdminResourcePage {initial} {config} />
