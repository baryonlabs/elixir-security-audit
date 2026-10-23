defmodule VulnApp.Search do
  @moduledoc "Filters product names with a user-supplied regular expression."

  @slug_pattern "^[a-z0-9-]+$"

  def filter(names, pattern) when is_binary(pattern) do
    # VULN: EXS-REDOS-001 (attacker chooses the regex, e.g. "^(a+)+$" -> catastrophic backtracking)
    regex = Regex.compile!(pattern)
    Enum.filter(names, &Regex.match?(regex, &1))
  end

  def valid_slug?(slug) do
    # SAFE: Regex.compile! on a developer-defined module constant, not user input
    Regex.match?(Regex.compile!(@slug_pattern), slug)
  end
end
