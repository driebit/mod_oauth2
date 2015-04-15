-module(mod_oauth2).
-author("Driebit <tech@driebit.nl>").

-mod_title("OAuth2").
-mod_description("Provides authentication over OAuth2.").
-mod_prio(400). %% Must be before mod_oauth
-mod_schema(1).
-mod_depends([mod_oauth]).

-export([
    init/1,
    observe_logon_ready_page/2,
    observe_service_authorize/2,
    manage_schema/2
]).

-include_lib("zotonic.hrl").

init(_Args) ->
    oauth2_server:init().

%% @doc When user has logged in, do OAuth authentication and retrieve token
-spec observe_logon_ready_page(#logon_ready_page{}, #context{}) -> string().
observe_logon_ready_page(#logon_ready_page{}, Context) ->
    case z_auth:is_auth(Context) of
        true ->
            %% Check for redirect_uri and client_id
            case z_context:get_q("redirect_uri", Context) of
                [] -> 
                    undefined;
                RedirectUri -> 
                    case z_context:get_q("client_id", Context) of
                        [] -> undefined;
                        ClientId ->
                            Code = oauth2_server:issue_code(ClientId, Context#context.user_id, Context),
                            UriWithCode = RedirectUri ++ "?code=" ++ Code,
                            UriWithCode
                    end
            end;
        false -> 
            []
    end.

observe_service_authorize(#service_authorize{service_module=_Module}, Context) ->
    ReqData = z_context:get_reqdata(Context),
    case get_access_token(ReqData) of
        undefined ->
            %% No OAuth2 request, but it may be OAuth1 or otherwise, so ignore
            undefined;
        AccessToken ->
            %% Validate access token
            case get_authenticated_context(AccessToken, Context) of
                undefined -> 
                    {{halt, 403}, ReqData, Context};
                AuthenticatedContext ->
                    {true, ReqData, AuthenticatedContext}
            end
    end.

manage_schema(install, Context) ->
    m_access_token:install(Context).

%% @doc Get access token from Authorization header
get_access_token(ReqData) ->
    Header = wrq:get_req_header_lc("authorization", ReqData),
    case string:tokens(Header, " ") of
        ["Bearer", AccessToken] ->
            AccessToken;
        _ ->
            %% No OAuth2 authorization header, so ignore
            undefined
    end.

get_authenticated_context(AccessToken, Context) ->
    case m_access_token:get(AccessToken, Context) of
        undefined ->
            {error, not_valid};
        CheckedToken ->
            case proplists:get_value(user_id, CheckedToken) of
                undefined ->
                    %% Client (not user) access token, so return user from 
                    %% app/client config
                    Client = oauth2_server:get_client(proplists:get_value(client_id, CheckedToken)),
                    ?DEBUG(Client);
                UserId ->
                    z_acl:logon(UserId, Context)        
            end
    end.
