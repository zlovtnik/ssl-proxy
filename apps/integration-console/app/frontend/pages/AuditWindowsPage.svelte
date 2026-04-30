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
      { key: "location_id", label: "Location", sortable: true, width: "w-32" },
      { key: "timezone", label: "Timezone", sortable: true, width: "w-36" },
      { key: "days", label: "Days", sortable: true, width: "w-32" },
      { key: "start_time", label: "Start", sortable: true, width: "w-24" },
      { key: "end_time", label: "End", sortable: true, width: "w-24" },
      { key: "enabled", label: "Enabled", sortable: true, width: "w-20", format: (value) => displayBoolean(value, "yes") || "no" }
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
