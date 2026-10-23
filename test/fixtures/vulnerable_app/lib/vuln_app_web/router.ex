defmodule VulnAppWeb.Router do
  use VulnAppWeb, :router

  # VULN: EXS-CFG-002 (browser pipeline is missing :put_secure_browser_headers)
  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :protect_from_forgery
  end

  pipeline :api do
    plug :accepts, ["json"]
  end

  scope "/", VulnAppWeb do
    pipe_through :browser

    get "/products", ProductController, :index
    get "/calc", CalcController, :show
    get "/search", SearchController, :index
    get "/download", DownloadController, :show
    get "/comments/preview", CommentController, :preview
    get "/preferences", PreferenceController, :show
  end

  scope "/api", VulnAppWeb do
    pipe_through :api

    post "/import", ApiController, :import
    post "/thumbnails", ApiController, :thumbnail
    get "/reports/orders", ApiController, :orders
    post "/feeds", ApiController, :feed
  end
end
