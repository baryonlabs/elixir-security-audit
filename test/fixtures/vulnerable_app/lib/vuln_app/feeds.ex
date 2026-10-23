defmodule VulnApp.Feeds do
  @moduledoc "Parses partner XML feeds (uses sweet_xml 0.6.6, see EXS-DEP-001)."

  import SweetXml

  def item_titles(xml) when is_binary(xml) do
    xml |> xpath(~x"//item/title/text()"ls)
  end
end
