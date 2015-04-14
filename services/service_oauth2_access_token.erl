-module(service_oauth2_access_token).
-author("Driebit <tech@driebit.nl>").

-svc_title("Retrieve an access token").

-svc_needauth(false).

-export([process_post/2]).

-include_lib("zotonic.hrl").

process_post(_ReqData, Context) ->
    ClientId = z_context:get_q("client_id", Context),
    ClientSecret = z_context:get_q("client_secret", Context),
    Code = z_context:get_q("code", Context),
    
    case oauth2_server:authorize_code_grant(ClientId, ClientSecret, Code, Context) of
        {error, Error} ->
            {error, Error, <<>>};
        Token ->
            z_convert:to_json(Token)
    end.
