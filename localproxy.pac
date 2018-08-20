function FindProxyForURL(url, host) {
		
	var privateIP = /^(0|10|127|192\.168|172\.1[6789]|172\.2[0-9]|172\.3[01]|169\.254|192\.88\.99)\.[0-9.]+$/;
	var resolved_ip = dnsResolve(host);
	var networktest_ip = dnsResolve("dns-test.spc.int");
	/* Don't send non-FQDN or private IP auths to us */
		if (isPlainHostName(host) || isInNet(resolved_ip, "192.0.2.0","255.255.255.0") || privateIP.test(host)) 
		return "DIRECT";
	
	//SPC addresses that should still use the proxy
	    if (shExpMatch(host, "lyris.spc.int")) return "PROXY 165.225.98.32:80; PROXY 175.45.116.32:80; DIRECT";
	    if (shExpMatch(host, "lists.spc.int")) return "PROXY 165.225.98.32:80; PROXY 175.45.116.32:80; DIRECT";
	    
	//Local Network Stuff
		if (shExpMatch(host, "*.corp.spc.int")) return "DIRECT";
		if (shExpMatch(host, "*.spc.local")) return "DIRECT";
		if (shExpMatch(host, "*.spbea.local")) return "DIRECT";
		if (shExpMatch(host, "*.spc.external")) return "DIRECT";
		if (shExpMatch(host, "*.spc.int")) return "DIRECT";
		if (shExpMatch(host, "*.sopac.org")) return "DIRECT";
		if (shExpMatch(host, "*.pacificdisaster.net")) return "DIRECT";
		if (shExpMatch(host, "*.sop.spc.lab")) return "DIRECT";
		
	// Send Okta auth traffic direct
		if (shExpMatch(host, "*.okta.com")) return "DIRECT";
		
	/* FTP goes directly */
		if (url.substring(0,4) == "ftp:") return "DIRECT";
		
    /* If outside of SPC as determined by the network test variable, send O365 URL's direct */
        if 
        (
            (networktest_ip != "172.19.1.15")
            &&
		    (
		    (dnsDomainIs(host, ".microsoftonline.com"))||
			(dnsDomainIs(host, ".office365.com")) ||
			(dnsDomainIs(host, ".outlook.com")) ||
			(dnsDomainIs(host, ".login.microsoft.com")) ||
			(dnsDomainIs(host, ".lync.com")) ||
			(dnsDomainIs(host, ".microsoftonline-p.com"))||
			(dnsDomainIs(host, ".microsoftonline-p.net")) ||
			(dnsDomainIs(host, ".microsoftonlineimages.com")) ||
			(dnsDomainIs(host, ".microsoftonlinesupport.net")) ||
			(dnsDomainIs(host, ".verisign.com")) ||
			(dnsDomainIs(host, ".symcb.com")) ||
			(dnsDomainIs(host, ".msocdn.com")) ||
			(dnsDomainIs(host, ".live.com")) ||
			(dnsDomainIs(host, ".office.net")) ||
			(dnsDomainIs(host, ".msecnd.net")) ||
			(dnsDomainIs(host, ".msn.com")) ||
			(dnsDomainIs(host, ".aadrm.com")) ||
			(dnsDomainIs(host, ".activedirectory.windowsazure.com")) ||
			(dnsDomainIs(host, "github-windows.s3.amazonaws.com")) ||
			(dnsDomainIs(host, ".yammer.com")) ||
			(dnsDomainIs(host, ".yammerusercontent.com")) ||
			(dnsDomainIs(host, ".assets-yammer.com")) ||
			(dnsDomainIs(host, ".cloudfront.net")) ||
			(dnsDomainIs(host, ".crocodoc.com")) ||
			(dnsDomainIs(host, ".whatismyip.com"))
			)
        )
        return "DIRECT";


	/* Updates are directly accessible */
		if (((localHostOrDomainIs(host, "trust.zscaler.com")) ||
				(localHostOrDomainIs(host, "trust.zscaler.net")) ||
				(localHostOrDomainIs(host, "trust.zscalerone.net")) ||
				(localHostOrDomainIs(host, "trust.zscalertwo.net")) ||
				(localHostOrDomainIs(host, "trust.zscloud.net")) ) &&
			(url.substring(0,5) == "http:" || url.substring(0,6) == "https:"))
		return "DIRECT";
		
	/* Default Traffic Forwarding. Forwarding to Zen on port 80, but you can use port 9400 also */
		return "PROXY 127.0.0.1:9000"; 
}
