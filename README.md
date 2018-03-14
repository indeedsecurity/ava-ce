# AVA - Another Vulnerability Auditor
AVA is a web scanner designed for use within automated systems. It accepts endpoints via HAR-formatted files and scans
each request with a set of checks and auditors. The checks determine the vulnerabilities to check, such as Cross-Site 
Scripting or Open Redirect. The auditors determine the HTTP elements to audit, such as parameters or cookies.

## Installation
Installing AVA:
```
pip3 install git+ssh://git@github.com/indeedsecurity/ava.git
```

## Scans
Scanning with default auditors and checks:
```
ava vectors.har
```

Scanning with specific auditors and checks:
```
ava -a parameter -e xss vectors.har
```

## Configuration
Configurations are specified via YAML files:
```
auditors
  - parameter
  - cookie
actives
  - xss
  - open_redirect
domain: ".example.com"
excludes:
  - /logout
agent: "Mozilla/5.0"
report: "report.json"
```

## Help
Displaying the help message:
```
ava -h
```

Displaying the list of auditors and checks:
```
ava -l
```

## Tests
Running tests:
```
pytest --cov-report=term-missing --cov=ava tests/
```

## License
AVA is licensed under the Apache License, Version 2.0.