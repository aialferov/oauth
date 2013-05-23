%%%-------------------------------------------------------------------
%%% @author Anton I Alferov <casper@ubca-dp>
%%% @copyright (C) 2013, Anton I Alferov
%%%
%%% Created: 23 May 2013 by Anton I Alferov <casper@ubca-dp>
%%%-------------------------------------------------------------------

-record(oauth_url, {uri, initiate, authorize, token}).

-define(OAuthUrl(Mode, Url), Url#oauth_url.uri ++ "/" ++ case Mode of
	initiate -> Url#oauth_url.initiate;
	authorize -> Url#oauth_url.authorize;
	token -> Url#oauth_url.token
end).
