-module(service_oauth2_me).
-author("Driebit <tech@driebit.nl>").

-svc_title("Retrieve an access token").

-svc_needauth(true).

-export([process_get/2]).

-include_lib("zotonic.hrl").

%% @doc Get user information
process_get(_ReqData, Context) ->
    %% Get user from context
    UserId = Context#context.user_id,
    z_convert:to_json(m_rsc_export:full(UserId, Context)).
    
    
    
