#!/usr/bin/env bash
set -euo pipefail

readonly max_columns=15
readonly repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$repo_root"

shopt -s nullglob
sql_files=(sql/tables/*.sql)
shopt -u nullglob

if ((${#sql_files[@]} == 0)); then
  echo "No table definitions found under sql/tables/." >&2
  exit 2
fi

awk -v max_columns="$max_columns" '
  function trim(value) {
    sub(/^[[:space:]]+/, "", value)
    sub(/[[:space:]]+$/, "", value)
    return value
  }

  function is_table_constraint(definition, normalized) {
    normalized = tolower(trim(definition))
    return normalized ~ /^(constraint|primary[[:space:]]+key|unique|check|foreign[[:space:]]+key|exclude|like)([[:space:](]|$)/
  }

  function finish_item() {
    if (trim(item) != "" && !is_table_constraint(item)) {
      column_count++
    }
    item = ""
  }

  function finish_table() {
    finish_item()
    table_count++

    if (column_count > max_columns) {
      if (!printed_heading) {
        printf "Postgres tables exceed the %d-column limit:\n", max_columns
        printed_heading = 1
      }
      printf "  %s:%d: %s has %d columns\n", table_file, table_line, table_name, column_count
      violation_count++
    }

    in_table = 0
    depth = 0
    in_single_quote = 0
    in_double_quote = 0
    in_block_comment = 0
    item = ""
  }

  function parse_table_text(text,    character, next_character, cursor) {
    for (cursor = 1; cursor <= length(text); cursor++) {
      character = substr(text, cursor, 1)
      next_character = substr(text, cursor + 1, 1)

      if (in_block_comment) {
        if (character == "*" && next_character == "/") {
          in_block_comment = 0
          cursor++
        }
        continue
      }

      if (in_single_quote) {
        item = item character
        if (character == "\047") {
          if (next_character == "\047") {
            item = item next_character
            cursor++
          } else {
            in_single_quote = 0
          }
        }
        continue
      }

      if (in_double_quote) {
        item = item character
        if (character == "\042") {
          if (next_character == "\042") {
            item = item next_character
            cursor++
          } else {
            in_double_quote = 0
          }
        }
        continue
      }

      if (character == "-" && next_character == "-") {
        break
      }

      if (character == "/" && next_character == "*") {
        in_block_comment = 1
        cursor++
        continue
      }

      if (depth == 0) {
        if (character == "(") {
          depth = 1
        }
        continue
      }

      if (character == "\047") {
        in_single_quote = 1
        item = item character
      } else if (character == "\042") {
        in_double_quote = 1
        item = item character
      } else if (character == "(") {
        depth++
        item = item character
      } else if (character == ")") {
        if (depth == 1) {
          finish_table()
          return
        }
        depth--
        item = item character
      } else if (character == "," && depth == 1) {
        finish_item()
      } else {
        item = item character
      }
    }

    if (in_table && depth > 0) {
      item = item " "
    }
  }

  FNR == 1 && in_table {
    printf "%s:%d: unterminated CREATE TABLE for %s\n", table_file, table_line, table_name > "/dev/stderr"
    parse_error = 1
    in_table = 0
    depth = 0
    in_single_quote = 0
    in_double_quote = 0
    in_block_comment = 0
    item = ""
  }

  {
    if (!in_table) {
      normalized_line = tolower($0)
      create_pattern = "^[[:space:]]*create[[:space:]]+(unlogged[[:space:]]+|temporary[[:space:]]+|temp[[:space:]]+)?table[[:space:]]+(if[[:space:]]+not[[:space:]]+exists[[:space:]]+)?"

      if (match(normalized_line, create_pattern)) {
        declaration = substr($0, RLENGTH + 1)
        table_name = declaration
        sub(/^[[:space:]]*/, "", table_name)
        sub(/[[:space:](].*$/, "", table_name)

        in_table = 1
        depth = 0
        column_count = 0
        item = ""
        table_file = FILENAME
        table_line = FNR
        parse_table_text(declaration)
      }
    } else {
      parse_table_text($0)
    }
  }

  END {
    if (in_table) {
      printf "%s:%d: unterminated CREATE TABLE for %s\n", table_file, table_line, table_name > "/dev/stderr"
      parse_error = 1
    }

    if (parse_error) {
      exit 2
    }
    if (violation_count) {
      exit 1
    }

    printf "Checked %d Postgres tables: all have at most %d columns.\n", table_count, max_columns
  }
' "${sql_files[@]}"
