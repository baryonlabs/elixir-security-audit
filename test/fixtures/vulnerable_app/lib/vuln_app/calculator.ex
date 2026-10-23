defmodule VulnApp.Calculator do
  @moduledoc "Spreadsheet-style formula evaluation."

  def evaluate(formula) when is_binary(formula) do
    # VULN: EXS-RCE-001 (Code.eval_string on a user-supplied formula = arbitrary code execution)
    {result, _binding} = Code.eval_string(formula)
    result
  end
end
