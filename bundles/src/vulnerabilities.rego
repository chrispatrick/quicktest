package vulnerabilities

	import future.keywords.if
	import future.keywords.in

	# there seems to be an issue preventing this from working
	# so for now it will return undefined decision if no failure
	# default fail := false

	# fail if {
	#	some vulnerability in input.vulnerabilities
	#	vulnerability.cvss.severity == "HIGH"
	# }

	
	fail if {
		some vulnerability in input.vulnerabilities
		vulnerability.cvss.severity == "HIGH"
		not input.prevVulnerabilities[vulnerability]
	}
