%%%-------------------------------------------------------------------
%%% @author Anton I Alferov <casper@ubca-dp>
%%% @copyright (C) 2013, Anton I Alferov
%%%
%%% Created: 04 Feb 2013 by Anton I Alferov <casper@ubca-dp>
%%%-------------------------------------------------------------------

-module(oauth_backend).

-export([get_request_token/2, get_access_token/2, refresh_access_token/2]).
-export([auth_header/4, auth_query/4]).

-include("oauth.hrl").
-include("oauth_backend.hrl").

-define(Version, "1.0").
-define(NonceFormat, [4]).

get_request_token(
	#oauth_consumer{key = ConsumerKey,
		secret = ConsumerSecret, callback = Callback},
	#oauth_config{url = Url,
		signature_method = SignatureMethod, options = Options}
) ->
	read_oauth(request_token(?OAuthUrl(initiate, Url), [
		{"oauth_callback", http_uri:encode(Callback)},
		{"oauth_consumer_key", ConsumerKey},
		{"oauth_nonce", generate_nonce()},
		{"oauth_signature_method", SignatureMethod},
		{"oauth_timestamp", timestamp()},
		{"oauth_version", ?Version}
	] ++ Options, ConsumerSecret)).

get_access_token(#oauth{
	consumer = #oauth_consumer{key = ConsumerKey, secret = ConsumerSecret},
	config = #oauth_config{url = Url, signature_method = SignatureMethod},
	token = #oauth_token{token = Token, secret = TokenSecret}
}, Verifier) ->
	read_oauth(request_token(?OAuthUrl(token, Url), [
		{"oauth_consumer_key", ConsumerKey},
		{"oauth_nonce", generate_nonce()},
		{"oauth_signature_method", SignatureMethod},
		{"oauth_timestamp", timestamp()},
		{"oauth_token", Token},
		{"oauth_verifier", Verifier},
		{"oauth_version", ?Version}
	], ConsumerSecret, TokenSecret)).

refresh_access_token(#oauth{
	consumer = #oauth_consumer{key = ConsumerKey, secret = ConsumerSecret},
	config = #oauth_config{url = Url, signature_method = SignatureMethod},
	token = #oauth_token{token = Token, secret = TokenSecret}
}, Options) ->
	read_oauth(request_token(?OAuthUrl(token, Url), [
		{"oauth_consumer_key", ConsumerKey},
		{"oauth_nonce", generate_nonce()},
		{"oauth_signature_method", SignatureMethod},
		{"oauth_timestamp", timestamp()},
		{"oauth_token", http_uri:encode(Token)},
		{"oauth_version", ?Version}
	] ++ Options, ConsumerSecret, TokenSecret)).

request_token(Url, Params, ConsumerSecret) ->
	request_token(Url, Params, ConsumerSecret, []).
request_token(Url, Params, ConsumerSecret, TokenSecret) ->
	Signature = signature(signature_method(
		utils_lists:keyfind2("oauth_signature_method", Params)),
		post, Url, Params, ConsumerSecret, TokenSecret
	),
	httpc:request(post, {Url, [], "application/x-www-form-urlencoded",
		utils_http:query_string([{"oauth_signature", Signature}|Params])
	}, [], []).

read_oauth({ok, {{_, 200, _}, _, Body}}) ->
	{ok, lists:foldl(fun({Key, Value}, T) -> case Key of
		"oauth_token" -> T#oauth_token{token = Value};
		"oauth_token_secret" -> T#oauth_token{secret = Value};
		"oauth_callback_confirmed" -> T;
		Key -> T#oauth_token{options = [{Key, Value}|T#oauth_token.options]}
	end end, #oauth_token{}, utils_http:read_query(Body))};
read_oauth({ok, {{_, _, _}, _, Body}}) -> {error, Body};
read_oauth(Error) -> Error.

auth_header(Method, Url, Params, OAuth = #oauth{
	consumer = #oauth_consumer{secret = ConsumerSecret},
	config = #oauth_config{realm = Realm, signature_method = SignatureMethod},
	token = #oauth_token{secret = TokenSecret}
}) ->
	AuthParams = auth_params(OAuth),
	Signature = signature(signature_method(SignatureMethod),
		Method, Url, Params ++ AuthParams, ConsumerSecret, TokenSecret),
	{"Authorization", "OAuth " ++ utils_http:header_string([
		{"realm", http_uri:encode(Realm)},
		{"oauth_signature", Signature}|AuthParams
	])}.

auth_query(Method, Url, Params, OAuth = #oauth{
	consumer = #oauth_consumer{secret = ConsumerSecret},
	config = #oauth_config{signature_method = SignatureMethod},
	token = #oauth_token{secret = TokenSecret}
}) ->
	AuthParams = auth_params(OAuth),
	Signature = signature(signature_method(SignatureMethod),
		Method, Url, Params ++ AuthParams, ConsumerSecret, TokenSecret),
	utils_http:query_string([{"oauth_signature", Signature}|AuthParams]).

auth_params(#oauth{
	consumer = #oauth_consumer{key = ConsumerKey},
	config = #oauth_config{signature_method = SignatureMethod},
	token = #oauth_token{token = Token}
}) -> [
	{"oauth_consumer_key", ConsumerKey},
	{"oauth_nonce", generate_nonce()},
	{"oauth_signature_method", SignatureMethod},
	{"oauth_timestamp", timestamp()},
	{"oauth_token", http_uri:encode(Token)},
	{"oauth_version", ?Version}
].

signature(plaintext, _Method, _Url, _Params, ConsumerSecret, TokenSecret) ->
	ConsumerSecret ++ "%26" ++ TokenSecret;
signature(hmac_sha1, Method, Url, Params, ConsumerSecret, TokenSecret) ->
	BaseString = method(Method) ++ "&" ++ http_uri:encode(Url) ++ "&" ++
		http_uri:encode(utils_http:query_string(lists:keysort(1, Params))),
	http_uri:encode(binary_to_list(base64:encode(crypto:hmac(
		sha, ConsumerSecret ++ "&" ++ TokenSecret, BaseString)))).

method(get) -> "GET";
method(put) -> "PUT";
method(post) -> "POST";
method(delete) -> "DELETE".

signature_method("HMAC-SHA1") -> hmac_sha1;
signature_method("PLAINTEXT") -> plaintext;
signature_method("plaintext") -> plaintext.

generate_nonce() -> utils_crypto:generate_nonce(?NonceFormat).

timestamp() ->
	{MSecs, Secs, _} = erlang:now(),
	integer_to_list(MSecs * 1000000 + Secs).
