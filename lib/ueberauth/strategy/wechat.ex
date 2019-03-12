defmodule Ueberauth.Strategy.Wechat do
  @moduledoc """
  Provides an Ueberauth strategy for authenticating with Wechat.

  ### Setup

  Include the provider in your configuration for Ueberauth

      config :ueberauth, Ueberauth,
        providers: [
          wechat: { Ueberauth.Strategy.Wechat, [] }
        ]

  Then include the configuration for wechat.

      config :ueberauth, Ueberauth.Strategy.Wechat.OAuth,
        client_id: System.get_env("WECHAT_APPID"),
        client_secret: System.get_env("WECHAT_SECRET")

  If you haven't already, create a pipeline and setup routes for your callback handler

      pipeline :auth do
        Ueberauth.plug "/auth"
      end

      scope "/auth" do
        pipe_through [:browser, :auth]

        get "/:provider/callback", AuthController, :callback
      end


  Create an endpoint for the callback where you will handle the `Ueberauth.Auth` struct

      defmodule MyApp.AuthController do
        use MyApp.Web, :controller

        def callback_phase(%{ assigns: %{ ueberauth_failure: fails } } = conn, _params) do
          # do things with the failure
        end

        def callback_phase(%{ assigns: %{ ueberauth_auth: auth } } = conn, params) do
          # do things with the auth
        end
      end

  """
  use Ueberauth.Strategy,
    uid_field: :unionid,
    default_scope: "snsapi_login",
    oauth2_module: Ueberauth.Strategy.Wechat.OAuth

  alias Ueberauth.Auth.Info
  alias Ueberauth.Auth.Credentials
  alias Ueberauth.Auth.Extra

  @doc """
  Handles the initial redirect to the wechat authentication page.

  To customize the scope (permissions) that are requested by wechat include them as part of your url:

      "/auth/wechat?scope=snsapi_userinfo"

  You can also include a `state` param that wechat will return to you.
  """
  def handle_request!(conn) do
    module = option(conn, :oauth2_module)
    scopes = conn.params["scope"] || option(conn, :default_scope)
    send_redirect_uri = Keyword.get(options(conn), :send_redirect_uri, true)
    config = conn.private[:ueberauth_request_options] |> Map.get(:options, [])
    redirect_uri = config[:redirect_uri] || callback_url(conn)
    state = conn.params["state"]

    params =
      if send_redirect_uri do
        [redirect_uri: redirect_uri, scope: scopes]
      else
        [scope: scopes]
      end

    params = if state, do: Keyword.put(params, :state, state), else: params

    if wechat_request?(conn) do
      redirect!(conn, apply(module, :authorize_url!, [params, [config: config]]))
    else
      redirect!(conn, apply(module, :qrcode_authorize_url!, [params, [config: config]]))
    end
  end

  def wechat_request?(conn) do
    user_agent = Plug.Conn.get_req_header(conn, "user-agent") |> List.first()

    if user_agent do
      user_agent |> String.contains?("MicroMessenger")
    else
      false
    end
  end

  @doc """
  Handles the callback from Wechat. When there is a failure from Wechat the failure is included in the
  `ueberauth_failure` struct. Otherwise the information returned from Wechat is returned in the `Ueberauth.Auth` struct.
  """
  def handle_callback!(%Plug.Conn{params: %{"code" => code}} = conn) do
    module = option(conn, :oauth2_module)

    client_options =
      conn.private
      |> Map.get(:ueberauth_request_options, [])
      |> Map.get(:options, [])

    options = [client_options: [config: client_options]]
    token = apply(module, :get_token!, [[code: code], [options: options]])

    if token.access_token |> to_string |> String.length() == 0 do
      set_errors!(conn, [
        error(token.other_params["error"], token.other_params["error_description"])
      ])
    else
      fetch_user(conn, token)
    end
  end

  @doc false
  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  @doc """
  Cleans up the private area of the connection used for passing the raw Wechat response around during the callback.
  """
  def handle_cleanup!(conn) do
    conn
    |> put_private(:wechat_user, nil)
    |> put_private(:wechat_token, nil)
  end

  @doc """
  Fetches the uid field from the Wechat response. This defaults to the option `uid_field` which in-turn defaults to `id`
  """
  def uid(conn) do
    uid_field =
      conn
      |> option(:uid_field)
      |> to_string

    if conn.private[:wechat_user] do
      conn.private.wechat_user[uid_field]
    end
  end

  @doc """
  Includes the credentials from the Wechat response.
  """
  def credentials(conn) do
    token = conn.private.wechat_token
    scope_string = token.other_params["scope"] || ""
    scopes = String.split(scope_string, ",", trim: true)

    %Credentials{
      token: token.access_token,
      refresh_token: token.refresh_token,
      expires_at: token.expires_at,
      token_type: token.token_type,
      expires: !!token.expires_at,
      scopes: scopes
    }
  end

  @doc """
  Fetches the fields to populate the info section of the `Ueberauth.Auth` struct.
  """
  def info(conn) do
    user = conn.private.wechat_user

    %Info{
      nickname: user["nickname"],
      image: user["headimgurl"]
    }
  end

  @doc """
  Stores the raw information (including the token) obtained from the Wechat callback.
  """
  def extra(conn) do
    %Extra{
      raw_info: %{
        token: conn.private.wechat_token,
        user: conn.private.wechat_user
      }
    }
  end

  def fetch_user(conn, token) do
    conn = put_private(conn, :wechat_token, token)

    case Ueberauth.Strategy.Wechat.OAuth.get(token, "/sns/userinfo") do
      {:ok, %OAuth2.Response{status_code: 401, body: _body}} ->
        set_errors!(conn, [error("token", "unauthorized")])

      {:ok, %OAuth2.Response{status_code: _status_code, body: user}} ->
        user = Poison.decode!(user)
        put_private(conn, :wechat_user, user)

      {:error, %OAuth2.Error{reason: reason}} ->
        set_errors!(conn, [error("OAuth2", reason)])
    end
  end

  defp option(conn, key) do
    Keyword.get(options(conn) || [], key, Keyword.get(default_options(), key))
  end
end
