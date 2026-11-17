# CI-only: Host/SNI application mapping for the identity test.
redef XbitsAppId::sni_suffix_to_app += {
	["facebook.com"] = "Facebook",
};

redef XbitsAppId::app_category += {
	["Facebook"] = "social",
};
