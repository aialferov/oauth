%%%-------------------------------------------------------------------
%%% @author Anton I Alferov <casper@ubca-dp>
%%% @copyright (C) 2013, Anton I Alferov
%%%
%%% Created: 04 Feb 2013 by Anton I Alferov <casper@ubca-dp>
%%%-------------------------------------------------------------------

-record(oauth, {consumer, config, token}).

-record(oauth_token, {token, secret, options = []}).
-record(oauth_consumer, {key, secret, callback}).
-record(oauth_config, {url, realm = "", signature_method, options = []}).
