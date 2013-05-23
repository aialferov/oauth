%%%-------------------------------------------------------------------
%%% @author Anton I Alferov <casper@ubca-dp>
%%% @copyright (C) 2013, Anton I Alferov
%%%
%%% Created: 23 May 2013 by Anton I Alferov <casper@ubca-dp>
%%%-------------------------------------------------------------------

-define(OAuthConfig(Network), case Network of
	dropbox -> #oauth_config{
		url = #oauth_url{uri = "https://api.dropbox.com/1/oauth",
			initiate = "request_token",
			authorize = "authorize",
			token = "access_token"
		},
		signature_method = "HMAC-SHA1"
	};
	twitter -> #oauth_config{
		url = #oauth_url{uri = "https://api.twitter.com/oauth",
			initiate = "request_token",
			authorize = "authorize",
			token = "access_token"
		},
		signature_method = "HMAC-SHA1"
	};
	yahoo -> #oauth_config{
		url = #oauth_url{uri = "https://api.login.yahoo.com/oauth/v2",
			initiate = "get_request_token",
			authorize = "request_auth",
			token = "get_token"
		},
		realm = "yahooapis.com",
		signature_method = "HMAC-SHA1",
		options = [
			{"xoauth_lang_pref", "en-us"}
		]
	}
end).
