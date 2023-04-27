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

	
	#fail if {
#		some vulnerability in input.vulnerabilities
#		vulnerability.cvss.severity == "HIGH"
#		not input.prevVulnerabilities[vulnerability]
#	}

	images := http.send({"url" : "http://localhost:8767/datalog-json/team/AQ1K5FIKA/queries", "method" : "POST", "raw_body", "{:queries [{:query [:find ?e :in $ :where [?e :schema/entity-type :docker/image]], :name "policy-evaluation"}]}", "headers" : { "Authorization": concat("Bearer ", input.authToken) }})
	
