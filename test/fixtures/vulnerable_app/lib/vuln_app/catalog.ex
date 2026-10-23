defmodule VulnApp.Catalog do
  @moduledoc "In-memory product catalog (no database needed)."

  @products [
    %{name: "anvil", price: 120, stock: 3},
    %{name: "bolt", price: 2, stock: 900},
    %{name: "crate", price: 35, stock: 40}
  ]

  # SAFE: String.to_atom on a compile-time module-attribute literal, never user input
  @default_sort String.to_atom("name")

  @sortable %{"name" => :name, "price" => :price, "stock" => :stock}

  def list_products, do: @products

  def default_sort, do: @default_sort

  @doc "Sorts by a user-supplied field name."
  def sort_products(field) when is_binary(field) do
    # VULN: EXS-ATOM-001 (user-controlled string turned into a new atom; atoms are never GC'd)
    key = String.to_atom(field)
    Enum.sort_by(@products, &Map.get(&1, key))
  end

  @doc "SAFE variant: allow-list lookup, unknown fields fall back to the default."
  def sort_products_safe(field) do
    key = Map.get(@sortable, field, @default_sort)
    Enum.sort_by(@products, &Map.fetch!(&1, key))
  end
end
