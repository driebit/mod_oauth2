-module(service_oauth2_access_token).
-author("Driebit <tech@driebit.nl>").

-svc_title("Retrieve an access token").

-svc_needauth(false).

-export([process_post/2]).

-include_lib("zotonic.hrl").

process_post(_ReqData, Context) ->
    GrantType = z_context:get_q("grant_type", Context),
    
    %% Validate required args client_id and client_secret
    case z_context:get_q("client_id", Context) of
        undefined -> {error, missing_arg, "client_id"};
        ClientId -> 
            case z_context:get_q("client_secret", Context) of
                undefined -> {error, missing_arg, "client_secret"};
                ClientSecret -> 
                    process_grant(GrantType, ClientId, ClientSecret, Context)                
            end
    end.

process_grant("client_credentials", ClientId, ClientSecret, Context) ->
    handle_grant_result(oauth2_server:client_credentials_grant(ClientId, ClientSecret, Context));
process_grant("authorization_code", ClientId, ClientSecret, Context) ->
    Code = z_context:get_q("code", Context),
    handle_grant_result(oauth2_server:authorize_code_grant(ClientId, ClientSecret, Code, Context));
process_grant(undefined, _, _, _Context) ->
    {error, missing_arg, "grant_type"};
process_grant(UnknownGrant, _, _, _Context) ->
    {error, invalid_arg, UnknownGrant}.

handle_grant_result({error, Reason}) ->
    {error, Reason, <<>>};
handle_grant_result(Token) ->
    z_convert:to_json(Token).
    
