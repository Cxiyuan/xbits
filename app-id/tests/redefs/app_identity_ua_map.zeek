# CI-only: User-Agent application mapping for the identity test.
redef XbitsAppId::ua_substr_to_app += {
	["dropbox"] = "Dropbox",
};

redef XbitsAppId::app_category += {
	["Dropbox"] = "cloud",
};
