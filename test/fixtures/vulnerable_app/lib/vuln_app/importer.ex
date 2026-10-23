defmodule VulnApp.Importer do
  @moduledoc "Imports JSON payloads posted by API clients."

  def import_payload(payload) when is_binary(payload) do
    # VULN: EXS-ATOM-002 (keys: :atoms creates an atom for every key in attacker-controlled JSON)
    Jason.decode(payload, keys: :atoms)
  end

  def import_payload_safe(payload) when is_binary(payload) do
    # SAFE: keys: :atoms! only converts keys to atoms that already exist
    Jason.decode(payload, keys: :atoms!)
  end
end
