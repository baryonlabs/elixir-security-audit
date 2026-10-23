defmodule VulnAppWeb.CommentHTML do
  use VulnAppWeb, :html

  # Trusted, developer-authored markup.
  @banner_html "<strong>Comments are moderated.</strong>"

  attr :comment, :string, required: true

  def preview(assigns) do
    ~H"""
    <section class="comment">
      <%!-- VULN: EXS-XSS-001 (user-supplied comment rendered unescaped via raw/1) --%>
      <p>{raw(@comment)}</p>
    </section>
    """
  end

  def banner do
    # SAFE: raw on a static, developer-authored module-attribute string
    Phoenix.HTML.raw(@banner_html)
  end
end
