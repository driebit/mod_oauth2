-module(service_oauth2_me).
-author("Driebit <tech@driebit.nl>").

-svc_title("Get user information").

%% Authentication is checked below: we don't want cookie/session authentication
%% to succeed so we check specifically for the OAuth2 token.
-svc_needauth(false).

-export([process_get/2]).

-include_lib("zotonic.hrl").

process_get(ReqData, Context) ->
    %% Must be user access token
    case mod_oauth2:get_access_token(ReqData, Context) of
        undefined ->
            %% Change to 401 when https://github.com/zotonic/zotonic/pull/962 is merged
            {error, access_denied, undefined};
        AccessToken -> 
            case proplists:get_value(user_id, AccessToken) of
                undefined -> 
                    %% A client access token, so return 403
                    {error, access_denied, undefined};
                UserId -> 
                    %% User access token
                    z_convert:to_json(m_rsc_export:full(UserId, Context))
            end
    end.
    
