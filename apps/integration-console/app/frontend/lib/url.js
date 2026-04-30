export function paramsFromLocation(defaults = {}) {
  const searchParams = new URLSearchParams(window.location.search)
  return {
    q: searchParams.get("q") || defaults.q || "",
    filters: filtersFromSearchParams(searchParams, defaults.filters || []),
    location_id: searchParams.get("location_id") || defaults.location_id || defaults.locationId || "",
    sort: searchParams.get("sort") || defaults.sort || defaults.sortKey || "",
    direction: searchParams.get("direction") || defaults.direction || defaults.sortDirection || "desc",
    page: positiveInteger(searchParams.get("page"), defaults.page || defaults.currentPage || 1),
    per_page: positiveInteger(searchParams.get("per_page"), defaults.per_page || defaults.perPage || 50)
  }
}

export function toQueryString(state, { includeBlank = false } = {}) {
  const params = new URLSearchParams()

  Object.entries(state).forEach(([key, value]) => {
    if (value === undefined || value === null) return
    if (!includeBlank && value === "") return
    params.set(key, value)
  })

  return params.toString()
}

export function updateHistory(path, state, replace = false) {
  const query = toQueryString(state)
  const url = query ? `${path}?${query}` : path
  const method = replace ? "replaceState" : "pushState"

  window.history[method]({ ...state }, "", url)
}

export function serializeFilters(filters = []) {
  const compact = filters
    .map((filter) => ({
      field: filter.field || "",
      operator: filter.operator || "",
      value: filter.value ?? "",
      conjunction: filter.conjunction === "OR" ? "OR" : "AND"
    }))
    .filter((filter) => filter.field && filter.operator)

  return compact.length ? JSON.stringify(compact) : ""
}

export function deserializeFilters(value, fallback = []) {
  if (!value) return fallback

  try {
    const parsed = JSON.parse(value)
    if (!Array.isArray(parsed)) return fallback

    return parsed.map((filter) => ({
      field: String(filter.field || ""),
      operator: String(filter.operator || ""),
      value: filter.value ?? "",
      conjunction: filter.conjunction === "OR" ? "OR" : "AND"
    }))
  } catch {
    return fallback
  }
}

export function filtersFromSearchParams(searchParams, fallback = []) {
  return deserializeFilters(searchParams.get("filters"), fallback)
}

export function toApiParams(filters = []) {
  const serialized = serializeFilters(filters)
  return serialized ? { filters: serialized } : {}
}

function positiveInteger(value, fallback) {
  const number = Number.parseInt(value, 10)
  return Number.isFinite(number) && number > 0 ? number : fallback
}
