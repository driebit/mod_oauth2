-module(oauth2_server).

-export([
    init/0,
    issue_code/3,
    authorize_code_grant/4,
    get_client/2
]).

-include("zotonic.hrl").

-define(CODE_TABLE, oauth2_code).

init() ->
    ets:new(?CODE_TABLE, [named_table, public]).

%% @doc Issue an authorization code (RFC 6749 4.1.2)
issue_code(ClientId, UserId, _Context) ->
    %% Generate a code
    Code = generate_code(),
    ets:insert(?CODE_TABLE, {Code, [{client_id, ClientId}, {user_id, UserId}]}),
    Code.

%% @doc Issue an access token (RFC 6749 4.1.4) for authorization_code grants
-spec authorize_code_grant(string(), string(), string(), #context{}) -> string().
authorize_code_grant(ClientId, ClientSecret, Code, Context) ->
    case ets:lookup(?CODE_TABLE, Code) of 
        [] ->
            {error, "unknown_code"};
        [{_Code, [{client_id, ClientId}, {user_id, UserId}]}] ->
            %% Authorization code found, check client secret
            case get_client(ClientId, Context) of
                [] -> 
                    lager:warning("Unknown client: ~p", [ClientId]);
                Client ->
                    %% Client exists
                    BinarySecret = z_convert:to_binary(ClientSecret),
                    case proplists:get_value(consumer_secret, Client) of
                        BinarySecret ->
                            %% Secret is correct
                            m_access_token:create(ClientId, UserId, Context);                    
                        TrueSecret ->
                            lager:warning("Secrets don't match: ~p and ~p", [BinarySecret, TrueSecret]),
                            {error, invalid_client}
                    end
            end;
        [{_Code, _}] ->
            %% When ClientId does not match
            lager:warning("Invalid code: ~p for client: ~p", [Code, ClientId])
    end.

get_client(Id, Context) ->
    m_oauth_app:get_consumer(z_convert:to_integer(Id), Context).
    
generate_code() ->
    base64:encode_to_string(crypto:hash(sha512, crypto:rand_bytes(100))).
