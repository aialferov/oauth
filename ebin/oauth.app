%%%-------------------------------------------------------------------
%%% Created: 21 Dec 2012 by Anton I Alferov <casper@ubca-dp>
%%%-------------------------------------------------------------------

{application, oauth, [
	{id, "oauth"},
	{vsn, "0.0.1"},
	{description, "Simple OAuth client"},
	{modules, [
		oauth,
		oauth_config,
		oauth_backend
	]},
	{registered, []},
	{applications, [kernel, stdlib, ssl, inets, utils]}
]}.
