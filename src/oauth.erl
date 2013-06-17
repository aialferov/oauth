%%%-------------------------------------------------------------------
%%% @author Anton I Alferov <casper@ubca-dp>
%%% @copyright (C) 2013, Anton I Alferov
%%%
%%% Created: 23 May 2013 by Anton I Alferov <casper@ubca-dp>
%%%-------------------------------------------------------------------

-module(oauth).

-export([start/0, stop/0]).
-export([auth_url/2, auth_result/1]).
-export([get_request_token/2, get_access_token/2, refresh_access_token/2]).
-export([auth_header/4, auth_query/4]).

-include("oauth.hrl").
-include("oauth_config.hrl").
-include("oauth_backend.hrl").

start() -> application:start(?MODULE).
stop() -> application:stop(?MODULE).

auth_url(Network, OAuth) -> utils_http:url(
	auth_uri(Network, OAuth), auth_params(Network, OAuth)).

auth_uri(_Network, OAuth) -> ?OAuthUrl(authorize,
	OAuth#oauth.config#oauth_config.url).

auth_params(dropbox, OAuth) -> auth_params(OAuth) ++
	[{"oauth_callback", OAuth#oauth.consumer#oauth_consumer.callback}];
auth_params(_Network, OAuth) -> auth_params(OAuth).
auth_params(OAuth) -> [{"oauth_token", OAuth#oauth.token#oauth_token.token}].

auth_result(Result) -> {ok, utils_lists:keyfind("oauth_verifier", Result)}.

get_request_token(Network, Consumer) when is_atom(Network) ->
	get_request_token(Consumer, ?OAuthConfig(Network));

get_request_token(Consumer, Config) ->
	case oauth_backend:get_request_token(Consumer, Config) of
		{ok, Token} -> {ok, #oauth{consumer = Consumer,
			config = Config, token = Token}};
		Error -> Error
	end.

get_access_token(OAuth, Verifier) ->
	case oauth_backend:get_access_token(OAuth, Verifier) of
		{ok, Token} -> {ok, OAuth#oauth{token = Token}};
		Error -> Error
	end.

refresh_access_token(Network, OAuth) when Network == yahoo ->
	case oauth_backend:refresh_access_token(
		OAuth, refresh_options(Network, OAuth))
	of
		{ok, Token} -> {ok, OAuth#oauth{token = Token}};
		Error -> Error
	end;

refresh_access_token(_, OAuth) -> {ok, OAuth}.

refresh_options(yahoo, OAuth) ->
	[lists:keyfind("oauth_session_handle", 1,
		OAuth#oauth.token#oauth_token.options)].

auth_header(Method, Url, Params, OAuth) ->
	oauth_backend:auth_header(Method, Url, Params, OAuth).

auth_query(Method, Url, Params, OAuth) ->
	oauth_backend:auth_query(Method, Url, Params, OAuth).
