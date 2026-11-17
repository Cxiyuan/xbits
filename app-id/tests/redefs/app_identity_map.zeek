# CI-only mapping data for the app-identity test.
# Production mapping is expected to be populated from app-id/mapping/*.map.
redef XbitsAppId::sni_suffix_to_app += {
	["facebook.com"] = "Facebook",
	["dropbox.com"] = "Dropbox",
};

redef XbitsAppId::ua_substr_to_app += {
	["dropbox"] = "Dropbox",
	["facebook"] = "Facebook",
};

redef XbitsAppId::app_category += {
	["Facebook"] = "social",
	["Dropbox"] = "cloud",
};
