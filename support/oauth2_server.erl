-module(oauth2_server).

-export([
    init/0,
    issue_code/2,
    authorize_code_grant/4,
    client_credentials_grant/3,
    get_client/2,
    get_client_by_title/2,
    create_client/5
]).

-include("zotonic.hrl").

-define(CODE_TABLE, oauth2_code).

init() ->
    ets:new(?CODE_TABLE, [named_table, public]).

%% @doc Issue an authorization code (RFC 6749 4.1.2)
-spec issue_code(string(), integer()) -> string().
issue_code(ClientId, UserId) ->
    %% Generate a code
    Code = generate_code(),
    ets:insert(?CODE_TABLE, {Code, [{client_id, ClientId}, {user_id, UserId}]}),
    Code.

%% @doc Issue an access token (RFC 6749 4.1.4) for authorization_code grants
-spec authorize_code_grant(string(), string(), string(), #context{}) -> string().
authorize_code_grant(ClientId, ClientSecret, Code, Context) ->
    case validate_client(ClientId, ClientSecret, Context) of
        {ok, _Client} ->
            case ets:lookup(?CODE_TABLE, Code) of 
                [] ->
                    {error, unknown_arg, "invalid code for this client"};
                [{_Code, [{client_id, ClientId}, {user_id, UserId}]}] ->
                    m_access_token:create(ClientId, UserId, Context);
                [{_Code, _}] ->
                    %% When code does not belong to this client
                    {error, unknown_arg, "invalid code for this client"}
            end;
        Error ->
            Error
    end.

client_credentials_grant(ClientId, ClientSecret, Context) ->
    case validate_client(ClientId, ClientSecret, Context) of
        {ok, _Client} ->
            m_access_token:create(ClientId, undefined, Context);
        Error -> 
            Error
    end.

validate_client(ClientId, ClientSecret, Context) ->
    case get_client(ClientId, Context) of
        [] -> 
            lager:warning("Unknown client: ~p", [ClientId]),
            {error, invalid_client};
        Client ->
            %% Client exists
            BinarySecret = z_convert:to_binary(ClientSecret),
            case proplists:get_value(consumer_secret, Client) of
                BinarySecret ->
                    {ok, Client};
                TrueSecret ->
                    lager:warning("Secrets don't match: ~p and ~p", [BinarySecret, TrueSecret]),
                    {error, invalid_client}
            end
    end.

get_client(Id, Context) ->
    m_oauth_app:get_consumer(z_convert:to_integer(Id), Context).

get_client_by_title(Title, Context) ->
    z_db:assoc_props_row("select * from oauth_application_registry where application_title=$1", [Title], Context).

create_client(Title, URL, Desc, Callback, Context) ->
    m_oauth_app:create_consumer(Title, URL, Desc, Callback, Context).

generate_code() ->
    base64:encode_to_string(crypto:hash(sha512, crypto:rand_bytes(100))).
