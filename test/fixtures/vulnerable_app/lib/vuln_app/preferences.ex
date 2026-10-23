defmodule VulnApp.Preferences do
  @moduledoc "User display preferences stored client-side in a cookie."

  def encode(prefs) when is_map(prefs), do: prefs |> :erlang.term_to_binary() |> Base.encode64()

  def decode(cookie) when is_binary(cookie) do
    raw = Base.decode64!(cookie)

    # VULN: EXS-DESER-001 (binary_to_term on attacker-controlled cookie: atom creation, funs, crafted terms)
    :erlang.binary_to_term(raw)
  end
end
