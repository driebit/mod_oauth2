-module(mod_oauth2).
-author("Driebit <tech@driebit.nl>").

-mod_title("OAuth2").
-mod_description("Provides authentication over OAuth2.").
-mod_prio(400).
-mod_schema(1).

-export([
    init/1,
    observe_logon_ready_page/2,
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

manage_schema(install, Context) ->
    m_access_token:install(Context).
