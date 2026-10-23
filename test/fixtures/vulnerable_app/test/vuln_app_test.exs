defmodule VulnAppTest do
  use ExUnit.Case, async: true

  alias VulnApp.{Catalog, Importer, Preferences, Reports, Search, Files, Feeds}

  test "safe sort falls back to default for unknown fields" do
    assert Catalog.default_sort() == :name
    assert [%{name: "anvil"} | _] = Catalog.sort_products_safe("bogus")
    assert [%{name: "bolt"} | _] = Catalog.sort_products_safe("price")
  end

  test "importer decodes with atom keys" do
    assert {:ok, %{name: "x"}} = Importer.import_payload(~s({"name":"x"}))
    assert {:ok, %{name: "x"}} = Importer.import_payload_safe(~s({"name":"x"}))
  end

  test "preferences round-trip through the cookie encoding" do
    assert Preferences.decode(Preferences.encode(%{theme: "dark"})) == %{theme: "dark"}
  end

  test "search filters and validates slugs" do
    assert Search.filter(["anvil", "bolt"], "^a") == ["anvil"]
    assert Search.valid_slug?("my-slug")
    refute Search.valid_slug?("Not A Slug")
  end

  test "safe file read rejects traversal" do
    assert {:ok, "hello from uploads\n"} = Files.read_upload_safe("readme.txt")
    assert {:error, :invalid_path} = Files.read_upload_safe("../../mix.exs")
  end

  test "reports build a query without hitting the database" do
    assert %Ecto.Query{} = Reports.recent_orders_query(10)
  end

  test "feeds extract titles" do
    xml = "<rss><item><title>a</title></item><item><title>b</title></item></rss>"
    assert Feeds.item_titles(xml) == ["a", "b"]
  end
end
