defmodule VulnApp.Thumbnails do
  @moduledoc "Generates thumbnails with ImageMagick."

  def generate(filename) when is_binary(filename) do
    # VULN: EXS-CMD-001 (filename is concatenated into a shell command line: "a.png; rm -rf ~")
    System.cmd("sh", ["-c", "convert " <> filename <> " -resize 100x100 priv/uploads/thumb.png"])
  end

  def generate_safe(filename) when is_binary(filename) do
    # SAFE: no shell; the executable is fixed and the filename is a single argv element
    System.cmd("convert", [filename, "-resize", "100x100", "priv/uploads/thumb.png"])
  end
end
