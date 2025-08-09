**JWTauditor**
**Overview**

JWTauditor is a professional passive JWT analysis extension for Burp Suite, designed to identify and analyze JSON Web Tokens (JWTs) in HTTP traffic. It automatically detects JWTs in requests and responses, analyzes them for security vulnerabilities, and provides detailed reports within Burp Suite's interface. The tool is optimized for security analysts and penetration testers to uncover common JWT-related vulnerabilities such as weak algorithms, expired tokens, and sensitive data exposure.

**Features**

Passive JWT Detection: Automatically identifies JWTs in HTTP headers, cookies, JSON bodies, and URL parameters.
Comprehensive Vulnerability Analysis:
Checks for alg: none vulnerabilities.
Detects expired tokens and invalid expiration claims.
Identifies weak or deprecated algorithms (e.g., HS256, RS256).
Flags sensitive claims (e.g., email, username, password).
Detects potential algorithm confusion and injection vulnerabilities.
Analyzes JWKS-related issues (e.g., insecure jku URLs).


User-Friendly Interface:
Dashboard tab with statistics on total JWTs analyzed and issue severity.
JWT Analysis tab with a detailed table of detected JWTs, including timestamps, endpoints, algorithms, and issues.
Configuration tab to customize vulnerability checks and sensitive claims.
History tab to track JWT reuse across requests.


Export Capabilities: Export analysis results as JSON or CSV for reporting.
Burp Suite Integration: Creates custom scan issues for detected vulnerabilities, integrated with Burp's Issues tab.
Context Menu Support: Manually trigger JWT analysis from Burp's Proxy History or Site Map.

**Requirements**

Burp Suite: Professional or Community edition.
Jython: Version 2.7.3 or later, configured in Burp Suite (Extender -> Options -> Python Environment).
Java: Compatible with Burp Suite's JVM (Java 8 or later recommended).

**Installation**

Download Jython:
Download the Jython standalone JAR (version 2.7.3 or later) from jython.org.
Configure Burp Suite to use Jython in Extender -> Options -> Python Environment by selecting the Jython JAR file.
Clone the repo.
Load the Extension:
In Burp Suite, go to Extender -> Extensions -> Add.
Set the extension type to Python.
Select the JWTauditor.py file.
Click Next to load the extension.


**Usage**

Configure Burp Suite:

Ensure the target application is in Burp's scope (Target -> Scope).
Use Burp's Proxy, Repeater, or other tools to capture HTTP traffic containing JWTs.

Automatic JWT Analysis:

JWTauditor passively scans HTTP requests and responses for JWTs in:
Authorization headers (Bearer tokens).
Cookies (e.g., session=eyJ...).
JSON bodies (e.g., {"token": "eyJ..."}).
URL parameters.
Detected JWTs are analyzed for vulnerabilities, and results are displayed in the "JWT Analysis" tab.



Review Results:

Dashboard Tab: View statistics on total JWTs analyzed and issues by severity (Critical, High, Medium).
JWT Analysis Tab: Browse a table of analyzed JWTs with details like endpoint, algorithm, and issues. Click a row to view header, payload, and issue details.
History Tab: Track JWT reuse across requests.
Issues Tab: Vulnerabilities are reported as custom Burp issues with detailed descriptions and remediation advice.


Export Reports:

In the "JWT Analysis" tab, click "Export Report" to save results as JSON or CSV.
Choose a file format and location in the dialog box.


Customize Configuration:

In the "Configuration" tab, enable/disable specific vulnerability checks (e.g., alg: none, expired tokens).
Update the list of sensitive claims to monitor (e.g., email, username, phone).
Click "Save Configuration" to apply changes.





**Known Limitations**

Requires Jython for Python-based execution in Burp Suite.
Passive analysis only; active JWT manipulation requires additional tools.
Limited to HTTP traffic captured by Burp Suite; ensure proper proxy configuration.

**Contributing**
Contributions are welcome! To contribute:

Fork the repository .
Create a feature branch .
Commit changes .
Push to the branch .
Open a pull request.

**License**
This project is licensed under the MIT License. See the LICENSE file for details.
Author
Developed by Mohamed Essam. For questions or feedback, contact mohamed.cybersec@gmail.com.
