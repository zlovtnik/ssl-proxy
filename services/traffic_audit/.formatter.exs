[
  inputs: [
    "{mix,.formatter}.exs",
    "{config,lib,test,mix}/**/*.{ex,exs}",
    "{guides}/**/*.md"
  ],
  locals_without_parens: [
    recipe: 2,
    recipe: 3,
    perform: 2,
    compute: 2,
    save: 2
  ],
  import_deps: [:ecto_sql, :myxql]
]
