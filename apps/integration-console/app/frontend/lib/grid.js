export function columnsToFilterFields(columns = []) {
  return columns
    .filter((column) => column.key && !column.key.startsWith("__"))
    .map((column) => ({
      key: column.filterKey || column.key,
      label: column.label || column.key,
      type: column.filterType || "text",
      options: column.filterOptions
    }))
}
