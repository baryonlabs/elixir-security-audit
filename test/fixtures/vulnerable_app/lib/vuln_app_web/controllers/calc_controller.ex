defmodule VulnAppWeb.CalcController do
  use VulnAppWeb, :controller

  def show(conn, %{"formula" => formula}) do
    result = VulnApp.Calculator.evaluate(formula)
    text(conn, inspect(result))
  end
end
