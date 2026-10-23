defmodule VulnApp.Files do
  @moduledoc "Serves files from the upload directory."

  @upload_dir "priv/uploads"

  def read_upload(name) when is_binary(name) do
    # VULN: EXS-PATH-001 (name = "../../config/prod.exs" escapes the upload directory)
    File.read!(Path.join(@upload_dir, name))
  end

  def read_upload_safe(name) when is_binary(name) do
    # SAFE: Path.safe_relative/2 rejects traversal outside the base directory
    case Path.safe_relative(name, @upload_dir) do
      {:ok, rel} -> File.read(Path.join(@upload_dir, rel))
      :error -> {:error, :invalid_path}
    end
  end
end
