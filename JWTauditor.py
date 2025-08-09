"""
Professional Passive JWTauditor Burp Suite Extension
Author: Mohamed Essam
Description: Comprehensive JWT security analysis extension for Burp Suite
Version: 1.0.0
"""

from burp import IBurpExtender, IHttpListener, ITab, IScanIssue, IContextMenuFactory, IContextMenuInvocation
from javax.swing import JPanel, JTable, JScrollPane, JTabbedPane, JLabel, JTextField, JButton, JCheckBox, JComboBox, JTextArea
from javax.swing import JSplitPane, JFrame, SwingUtilities, JOptionPane, JFileChooser, BorderFactory
from javax.swing.table import DefaultTableModel, TableRowSorter
from java.awt import BorderLayout, FlowLayout, Color, Font, Dimension, GridBagLayout, GridBagConstraints, Insets
from java.awt.event import ActionListener, MouseAdapter, MouseEvent
from java.util import ArrayList
from java.net import URL
from javax.swing.filechooser import FileNameExtensionFilter
import json
import base64
import re
import time
import hashlib
import threading
from collections import defaultdict

class BurpJWT:
    """Professional JWT implementation optimized for Burp Suite"""
    
    @staticmethod
    def decode(token, verify=False, options=None):
        """Decode JWT without verification (security analysis mode)"""
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")
            
        try:
            payload = json.loads(BurpJWT._base64url_decode(parts[1]))
            return payload
        except Exception as e:
            raise ValueError("Invalid JWT payload: {}".format(str(e)))
    
    @staticmethod
    def get_unverified_header(token):
        """Get JWT header without verification"""
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")
            
        try:
            return json.loads(BurpJWT._base64url_decode(parts[0]))
        except Exception as e:
            raise ValueError("Invalid JWT header: {}".format(str(e)))
    
    @staticmethod
    def _base64url_decode(data):
        """Base64URL decode with proper padding"""
        padding = 4 - len(data) % 4
        if padding != 4:
            data += '=' * padding
        return base64.urlsafe_b64decode(data)

pyjwt = BurpJWT()
JWT_AVAILABLE = True

class BurpExtender(IBurpExtender, IHttpListener, ITab, IContextMenuFactory):
    
    def __init__(self):
        self.extension_name = "JWTauditor"
        self.jwt_cache = {}
        self.analyzed_jwts = []
        self.jwt_history = defaultdict(list)
        self.sensitive_claims = [
            "email", "username", "password", "admin", "role", "permissions", 
            "phone", "address", "ssn", "credit_card", "api_key", "secret",
            "token", "refresh_token", "user_id", "account_id"
        ]
        self.config = {
            "check_alg_none": True,
            "check_expired": True,
            "check_weak_algorithms": True,
            "check_sensitive_claims": True,
            "check_missing_kid": True,
            "verbosity": "medium",
            "auto_fetch_jwks": False
        }
        self.weak_algorithms = ["HS256", "RS256"]
        self.jwt_regex = re.compile(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')
        
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName(self.extension_name)
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        self.init_ui()
        callbacks.addSuiteTab(self)
        print("[+] {} loaded successfully".format(self.extension_name))
    
    def init_ui(self):
        self.main_panel = JPanel(BorderLayout())
        self.tabbed_pane = JTabbedPane()
        self.dashboard_panel = self.create_dashboard_tab()
        self.tabbed_pane.addTab("Dashboard", self.dashboard_panel)
        self.analysis_panel = self.create_analysis_tab()
        self.tabbed_pane.addTab("JWT Analysis", self.analysis_panel)
        self.config_panel = self.create_config_tab()
        self.tabbed_pane.addTab("Configuration", self.config_panel)
        self.history_panel = self.create_history_tab()
        self.tabbed_pane.addTab("History", self.history_panel)
        
        self.main_panel.add(self.tabbed_pane, BorderLayout.CENTER)
    
    def create_dashboard_tab(self):
        panel = JPanel(BorderLayout())
        stats_panel = JPanel(GridBagLayout())
        stats_panel.setBorder(BorderFactory.createTitledBorder("JWT Analysis Statistics"))
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.gridx, gbc.gridy = 0, 0
        stats_panel.add(JLabel("Total JWTs Analyzed:"), gbc)
        gbc.gridx = 1
        self.total_jwts_label = JLabel("0")
        self.total_jwts_label.setFont(Font("Arial", Font.BOLD, 14))
        stats_panel.add(self.total_jwts_label, gbc)
        gbc.gridx, gbc.gridy = 0, 1
        stats_panel.add(JLabel("Critical Issues:"), gbc)
        gbc.gridx = 1
        self.critical_issues_label = JLabel("0")
        self.critical_issues_label.setForeground(Color.RED)
        self.critical_issues_label.setFont(Font("Arial", Font.BOLD, 14))
        stats_panel.add(self.critical_issues_label, gbc)
        gbc.gridx, gbc.gridy = 0, 2
        stats_panel.add(JLabel("High Issues:"), gbc)
        gbc.gridx = 1
        self.high_issues_label = JLabel("0")
        self.high_issues_label.setForeground(Color.ORANGE)
        self.high_issues_label.setFont(Font("Arial", Font.BOLD, 14))
        stats_panel.add(self.high_issues_label, gbc)
        gbc.gridx, gbc.gridy = 0, 3
        stats_panel.add(JLabel("Medium Issues:"), gbc)
        gbc.gridx = 1
        self.medium_issues_label = JLabel("0")
        self.medium_issues_label.setForeground(Color.YELLOW.darker())
        self.medium_issues_label.setFont(Font("Arial", Font.BOLD, 14))
        stats_panel.add(self.medium_issues_label, gbc)
        
        panel.add(stats_panel, BorderLayout.NORTH)
        activity_panel = JPanel(BorderLayout())
        activity_panel.setBorder(BorderFactory.createTitledBorder("Recent Activity"))
        
        self.activity_text = JTextArea(10, 50)
        self.activity_text.setEditable(False)
        activity_scroll = JScrollPane(self.activity_text)
        activity_panel.add(activity_scroll, BorderLayout.CENTER)
        
        panel.add(activity_panel, BorderLayout.CENTER)
        
        return panel
    
    def create_analysis_tab(self):
        panel = JPanel(BorderLayout())
        self.table_model = DefaultTableModel()
        self.table_model.addColumn("Timestamp")
        self.table_model.addColumn("Endpoint")
        self.table_model.addColumn("JWT (Partial)")
        self.table_model.addColumn("Algorithm")
        self.table_model.addColumn("Expired")
        self.table_model.addColumn("Issues")
        self.table_model.addColumn("Severity")
        
        self.jwt_table = JTable(self.table_model)
        self.jwt_table.setAutoCreateRowSorter(True)
        self.jwt_table.addMouseListener(JWTTableMouseListener(self))
        
        table_scroll = JScrollPane(self.jwt_table)
        split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        split_pane.setTopComponent(table_scroll)
        details_panel = self.create_details_panel()
        split_pane.setBottomComponent(details_panel)
        split_pane.setDividerLocation(300)
        
        panel.add(split_pane, BorderLayout.CENTER)
        control_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        
        export_button = JButton("Export Report")
        export_button.addActionListener(ExportActionListener(self))
        control_panel.add(export_button)
        
        clear_button = JButton("Clear Results")
        clear_button.addActionListener(ClearActionListener(self))
        control_panel.add(clear_button)
        
        panel.add(control_panel, BorderLayout.NORTH)
        
        return panel
    
    def create_details_panel(self):
        panel = JPanel(BorderLayout())
        details_tabs = JTabbedPane()
        self.header_text = JTextArea(5, 50)
        self.header_text.setEditable(False)
        self.header_text.setFont(Font("Courier New", Font.PLAIN, 12))
        header_scroll = JScrollPane(self.header_text)
        details_tabs.addTab("Header", header_scroll)
        self.payload_text = JTextArea(5, 50)
        self.payload_text.setEditable(False)
        self.payload_text.setFont(Font("Courier New", Font.PLAIN, 12))
        payload_scroll = JScrollPane(self.payload_text)
        details_tabs.addTab("Payload", payload_scroll)
        self.issues_text = JTextArea(5, 50)
        self.issues_text.setEditable(False)
        self.issues_text.setFont(Font("Courier New", Font.PLAIN, 12))
        issues_scroll = JScrollPane(self.issues_text)
        details_tabs.addTab("Issues", issues_scroll)
        
        panel.add(details_tabs, BorderLayout.CENTER)
        
        return panel
    
    def create_config_tab(self):
        panel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.anchor = GridBagConstraints.WEST
        gbc.gridx, gbc.gridy = 0, 0
        gbc.gridwidth = 2
        panel.add(JLabel("Vulnerability Checks:"), gbc)
        
        gbc.gridwidth = 1
        gbc.gridy = 1
        self.check_alg_none = JCheckBox("Check for 'alg: none'", self.config["check_alg_none"])
        panel.add(self.check_alg_none, gbc)
        
        gbc.gridy = 2
        self.check_expired = JCheckBox("Check for expired tokens", self.config["check_expired"])
        panel.add(self.check_expired, gbc)
        
        gbc.gridy = 3
        self.check_weak_alg = JCheckBox("Check for weak algorithms", self.config["check_weak_algorithms"])
        panel.add(self.check_weak_alg, gbc)
        
        gbc.gridy = 4
        self.check_sensitive = JCheckBox("Check for sensitive claims", self.config["check_sensitive_claims"])
        panel.add(self.check_sensitive, gbc)
        gbc.gridy = 6
        gbc.gridwidth = 2
        panel.add(JLabel("Sensitive Claims (comma-separated):"), gbc)
        
        gbc.gridy = 7
        self.sensitive_claims_field = JTextField(", ".join(self.sensitive_claims), 50)
        panel.add(self.sensitive_claims_field, gbc)
        gbc.gridy = 8
        save_config_button = JButton("Save Configuration")
        save_config_button.addActionListener(SaveConfigActionListener(self))
        panel.add(save_config_button, gbc)
        
        return panel
    
    def create_history_tab(self):
        panel = JPanel(BorderLayout())
        self.history_model = DefaultTableModel()
        self.history_model.addColumn("Timestamp")
        self.history_model.addColumn("Endpoint")
        self.history_model.addColumn("JWT Hash")
        self.history_model.addColumn("Reuse Count")
        self.history_model.addColumn("Status")
        
        history_table = JTable(self.history_model)
        history_scroll = JScrollPane(history_table)
        
        panel.add(history_scroll, BorderLayout.CENTER)
        
        return panel
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        try:
            if messageIsRequest:
                message = messageInfo.getRequest()
                message_type = "Request"
            else:
                message = messageInfo.getResponse()
                message_type = "Response"
                
            if message is None:
                return
            message_str = self._helpers.bytesToString(message)
            jwts = self.extract_jwts(message_str, messageInfo.getUrl())
            for jwt_data in jwts:
                self.analyze_jwt(jwt_data, messageInfo, message_type)
                
        except Exception as e:
            print("[!] Error processing HTTP message: {}".format(str(e)))
    
    def extract_jwts(self, message, url):
        jwts = []
        message_str = self._helpers.bytesToString(message)
        matches = self.jwt_regex.findall(message_str)
        for match in matches:
            if self.is_valid_jwt_structure(match):
                jwt_data = {
                    "token": match,
                    "location": self.determine_jwt_location(message_str, match),
                    "url": str(url),
                    "timestamp": time.time()
                }
                jwts.append(jwt_data)
        try:
            headers = self._helpers.analyzeRequest(message).getHeaders()
            for header in headers:
                if header.lower().startswith(("cookie:", "set-cookie:")):
                    cookie_str = header.split(":", 1)[1].strip()
                    cookies = cookie_str.split(";")
                    for cookie in cookies:
                        cookie = cookie.strip()
                        if "=" in cookie:
                            name, value = cookie.split("=", 1)
                            value = value.strip()
                            if self.jwt_regex.match(value) and self.is_valid_jwt_structure(value):
                                jwt_data = {
                                    "token": value,
                                    "location": "Cookie: {}".format(name.strip()),
                                    "url": str(url),
                                    "timestamp": time.time()
                                }
                                jwts.append(jwt_data)
        except Exception as e:
            print("[!] Error parsing cookies: {}".format(str(e)))
        
        return jwts
    
    def is_valid_jwt_structure(self, token):
        parts = token.split('.')
        if len(parts) != 3:
            return False
            
        for i, part in enumerate(parts[:2]):
            try:
                decoded = self.base64url_decode(part)
                json.loads(decoded)
            except Exception as e:
                print("[DEBUG] Validation failed for part {} ({}): {}".format(i, part, str(e)))
                return False
                
        return True
    
    def determine_jwt_location(self, message, jwt):
        if "Authorization: Bearer {}".format(jwt) in message:
            return "Authorization Header"
        if '"token": "{}"'.format(jwt) in message or "'token': '{}'".format(jwt) in message:
            return "JSON Body"
        if "Cookie:" in message or "Set-Cookie:" in message:
            headers = message.split('\n')
            for header in headers:
                if header.strip().startswith(("Cookie:", "Set-Cookie:")):
                    cookie_str = header.strip().split(":", 1)[1].strip()
                    cookies = cookie_str.split(";")
                    for cookie in cookies:
                        cookie = cookie.strip()
                        if "=" in cookie:
                            name, value = cookie.split("=", 1)
                            if value.strip() == jwt:
                                return "Cookie: {}".format(name.strip())
        if jwt in message and ("?" in message or "#" in message):
            return "URL Parameter"
        
        return "Unknown"
    
    def analyze_jwt(self, jwt_data, message_info, message_type):
        try:
            token = jwt_data["token"]
            token_hash = hashlib.md5(token.encode()).hexdigest()
            if token_hash in self.jwt_cache:
                return
            parsed_jwt = self.parse_jwt(token)
            if not parsed_jwt:
                return
            issues = self.check_vulnerabilities(parsed_jwt, jwt_data)
            result = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(jwt_data["timestamp"])),
                "endpoint": jwt_data["url"],
                "token": token,
                "token_partial": token[:20] + "..." if len(token) > 20 else token,
                "location": jwt_data["location"],
                "header": parsed_jwt["header"],
                "payload": parsed_jwt["payload"],
                "signature": parsed_jwt["signature"],
                "issues": issues,
                "message_type": message_type,
                "message_info": message_info
            }
            self.jwt_cache[token_hash] = result
            self.analyzed_jwts.append(result)
            self.update_jwt_history(token, jwt_data["url"])
            SwingUtilities.invokeLater(lambda: self.update_ui(result))
            if issues:
                self.create_burp_issues(result, message_info)
                
        except Exception as e:
            print("[!] Error analyzing JWT: {}".format(str(e)))
    
    def parse_jwt(self, token):
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
                
            header = json.loads(self.base64url_decode(parts[0]))
            payload = json.loads(self.base64url_decode(parts[1]))
            signature = parts[2]
            
            return {
                "header": header,
                "payload": payload,
                "signature": signature,
                "raw_token": token
            }
            
        except Exception as e:
            print("[!] Error parsing JWT: {} for token {}".format(str(e), token[:20] + "..."))
            return None
    
    def base64url_decode(self, data):
        """Decode base64url encoded data"""
        try:
            if isinstance(data, unicode):
                data = data.encode('utf-8')
            elif not isinstance(data, str):
                data = str(data)
            padding = 4 - len(data) % 4
            if padding != 4:
                data += '=' * padding
            decoded = base64.urlsafe_b64decode(data)
            if isinstance(decoded, bytes):
                decoded = decoded.decode('utf-8')
                
            return decoded
        except Exception as e:
            print("[!] Base64 decode error: {} for data: {}".format(str(e), data))
            raise
    
    def check_vulnerabilities(self, parsed_jwt, jwt_data):
        header = parsed_jwt["header"]
        payload = parsed_jwt["payload"]
        issues = []
        
        if self.config["check_alg_none"] and header.get("alg", "").lower() == "none":
            issues.append({
                "severity": "Critical",
                "type": "Algorithm None",
                "description": "JWT uses 'alg: none' which allows token forgery",
                "recommendation": "Use a secure algorithm like RS256 or HS256"
            })
        if self.config["check_expired"] and "exp" in payload:
            try:
                exp_time = int(payload["exp"])
                current_time = int(time.time())
                if exp_time < current_time:
                    expired_duration = current_time - exp_time
                    issues.append({
                        "severity": "High",
                        "type": "Expired Token",
                        "description": "JWT expired {} seconds ago".format(expired_duration),
                        "recommendation": "Implement proper token expiration validation"
                    })
            except (ValueError, TypeError):
                pass
        if self.config["check_weak_algorithms"]:
            alg = header.get("alg", "")
            if alg in self.weak_algorithms:
                issues.append({
                    "severity": "Medium",
                    "type": "Weak Algorithm",
                    "description": "JWT uses potentially weak algorithm: {}".format(alg),
                    "recommendation": "Consider using RS256 for better security"
                })
        if self.config["check_sensitive_claims"]:
            for claim_name, claim_value in payload.items():
                if claim_name.lower() in [sc.lower() for sc in self.sensitive_claims]:
                    issues.append({
                        "severity": "Medium",
                        "type": "Sensitive Claim",
                        "description": "Sensitive claim '{}' found in JWT payload".format(claim_name),
                        "recommendation": "Avoid exposing sensitive data in JWT claims"
                    })
        if "kid" in header:
            kid_value = str(header["kid"])
            suspicious_patterns = ["../", "http://", "https://", "file://", "null", "none"]
            for pattern in suspicious_patterns:
                if pattern in kid_value.lower():
                    issues.append({
                        "severity": "High",
                        "type": "Suspicious Key ID",
                        "description": "JWT 'kid' parameter contains suspicious value: {}".format(kid_value),
                        "recommendation": "Validate 'kid' parameter and ensure it references legitimate keys"
                    })
                    break
        
        return issues
    
    def update_jwt_history(self, token, url):
        token_hash = hashlib.md5(token.encode()).hexdigest()
        self.jwt_history[token_hash].append({
            "timestamp": time.time(),
            "url": url
        })
    
    def update_ui(self, result):
        try:
            severity = self.get_highest_severity(result["issues"])
            issues_summary = ", ".join([issue["type"] for issue in result["issues"]])
            
            row = [
                result["timestamp"],
                result["endpoint"],
                result["token_partial"],
                result["header"].get("alg", "Unknown"),
                "Yes" if any(issue["type"] == "Expired Token" for issue in result["issues"]) else "No",
                issues_summary,
                severity
            ]
            
            self.table_model.addRow(row)
            self.update_statistics()
            activity_msg = "[{}] JWT analyzed from {} (Location: {}) - {} issues found\n".format(
                result["timestamp"], 
                result["endpoint"], 
                result["location"], 
                len(result["issues"])
            )
            self.activity_text.append(activity_msg)
            self.activity_text.setCaretPosition(self.activity_text.getDocument().getLength())
            
        except Exception as e:
            print("[!] Error updating UI: {}".format(str(e)))
    
    def update_statistics(self):
        total_jwts = len(self.analyzed_jwts)
        critical_issues = 0
        high_issues = 0
        medium_issues = 0
        
        for result in self.analyzed_jwts:
            for issue in result["issues"]:
                if issue["severity"] == "Critical":
                    critical_issues += 1
                elif issue["severity"] == "High":
                    high_issues += 1
                elif issue["severity"] == "Medium":
                    medium_issues += 1
        
        self.total_jwts_label.setText(str(total_jwts))
        self.critical_issues_label.setText(str(critical_issues))
        self.high_issues_label.setText(str(high_issues))
        self.medium_issues_label.setText(str(medium_issues))
    
    def get_highest_severity(self, issues):
        if not issues:
            return "None"
            
        severities = ["Critical", "High", "Medium", "Low"]
        for severity in severities:
            if any(issue["severity"] == severity for issue in issues):
                return severity
                
        return "Low"
    
    def create_burp_issues(self, result, message_info):
        try:
            for issue in result["issues"]:
                burp_issue = JWTScanIssue(
                    message_info.getHttpService(),
                    message_info.getUrl(),
                    [message_info],
                    issue,
                    result
                )
                self._callbacks.addScanIssue(burp_issue)
        except Exception as e:
            print("[!] Error creating Burp issues: {}".format(str(e)))
    
    def createMenuItems(self, invocation):
        menu_items = ArrayList()
        
        if invocation.getInvocationContext() in [
            IContextMenuInvocation.CONTEXT_PROXY_HISTORY,
            IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE
        ]:
            menu_item = JWTContextMenuItem("Analyze JWT", invocation, self)
            menu_items.add(menu_item)
            
        return menu_items
    
    def getTabCaption(self):
        return "JWT Analyzer"
    
    def getUiComponent(self):
        return self.main_panel

class JWTScanIssue(IScanIssue):
    
    def __init__(self, http_service, url, http_messages, issue, result):
        self._http_service = http_service
        self._url = url
        self._http_messages = http_messages
        self._issue = issue
        self._result = result
    
    def getUrl(self):
        return self._url
    
    def getIssueName(self):
        return "JWT Vulnerability - {}".format(self._issue["type"])
    
    def getIssueType(self):
        return 0x08000000
    
    def getSeverity(self):
        severity_map = {
            "Critical": "High",
            "High": "High", 
            "Medium": "Medium",
            "Low": "Low"
        }
        return severity_map.get(self._issue["severity"], "Information")
    
    def getConfidence(self):
        return "Certain"
    
    def getIssueBackground(self):
        return "JSON Web Tokens (JWTs) are commonly used for authentication and authorization. Various security issues can arise from improper JWT implementation."
    
    def getRemediationBackground(self):
        return "Ensure proper JWT implementation following security best practices including secure algorithms, proper validation, and avoiding sensitive data in claims."
    
    def getIssueDetail(self):
        detail = "JWT Vulnerability Details:\n\n"
        detail += "Issue Type: {}\n".format(self._issue["type"])
        detail += "Severity: {}\n".format(self._issue["severity"])
        detail += "Description: {}\n".format(self._issue["description"])
        detail += "\nJWT Header: {}\n".format(json.dumps(self._result["header"], indent=2))
        detail += "\nJWT Payload: {}\n".format(json.dumps(self._result["payload"], indent=2))
        return detail
    
    def getRemediationDetail(self):
        return self._issue["recommendation"]
    
    def getHttpMessages(self):
        return self._http_messages
    
    def getHttpService(self):
        return self._http_service

class JWTTableMouseListener(MouseAdapter):
    
    def __init__(self, burp_extender):
        self.burp_extender = burp_extender
    
    def mouseClicked(self, event):
        if event.getClickCount() == 1:
            row = self.burp_extender.jwt_table.getSelectedRow()
            if row >= 0:
                self.show_jwt_details(row)
    
    def show_jwt_details(self, row):
        try:
            if row < len(self.burp_extender.analyzed_jwts):
                result = self.burp_extender.analyzed_jwts[row]
                header_text = json.dumps(result["header"], indent=2)
                self.burp_extender.header_text.setText(header_text)
                payload_text = json.dumps(result["payload"], indent=2)
                self.burp_extender.payload_text.setText(payload_text)
                issues_text = ""
                for issue in result["issues"]:
                    issues_text += "[{}] {}\n".format(issue["severity"], issue["type"])
                    issues_text += "Description: {}\n".format(issue["description"])
                    issues_text += "Recommendation: {}\n\n".format(issue["recommendation"])
                
                if not issues_text:
                    issues_text = "No issues detected."
                    
                self.burp_extender.issues_text.setText(issues_text)
                
        except Exception as e:
            print("[!] Error showing JWT details: {}".format(str(e)))

class JWTContextMenuItem(object):
    
    def __init__(self, caption, invocation, burp_extender):
        self._caption = caption
        self._invocation = invocation
        self._burp_extender = burp_extender
    
    def getCaption(self):
        return self._caption
    
    def menuItemClicked(self):
        messages = self._invocation.getSelectedMessages()
        for message in messages:
            self._burp_extender.processHttpMessage(0, False, message)

class ExportActionListener(ActionListener):
    
    def __init__(self, burp_extender):
        self.burp_extender = burp_extender
    
    def actionPerformed(self, event):
        try:
            file_chooser = JFileChooser()
            file_chooser.setDialogTitle("Export JWT Analysis Report")
            json_filter = FileNameExtensionFilter("JSON Files", ["json"])
            csv_filter = FileNameExtensionFilter("CSV Files", ["csv"])
            file_chooser.addChoosableFileFilter(json_filter)
            file_chooser.addChoosableFileFilter(csv_filter)
            
            result = file_chooser.showSaveDialog(None)
            if result == JFileChooser.APPROVE_OPTION:
                file_path = file_chooser.getSelectedFile().getAbsolutePath()
                file_filter = file_chooser.getFileFilter()
                
                if isinstance(file_filter, FileNameExtensionFilter):
                    if "json" in file_filter.getExtensions():
                        self.export_json(file_path)
                    elif "csv" in file_filter.getExtensions():
                        self.export_csv(file_path)
                else:
                    self.export_json(file_path)
                    
                JOptionPane.showMessageDialog(None, "Report exported successfully!")
                
        except Exception as e:
            JOptionPane.showMessageDialog(None, "Error exporting report: {}".format(str(e)))
    
    def export_json(self, file_path):
        export_data = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_jwts": len(self.burp_extender.analyzed_jwts),
            "results": []
        }
        
        for result in self.burp_extender.analyzed_jwts:
            export_result = {
                "timestamp": result["timestamp"],
                "endpoint": result["endpoint"],
                "location": result["location"],
                "algorithm": result["header"].get("alg", "Unknown"),
                "header": result["header"],
                "payload": result["payload"],
                "issues": result["issues"]
            }
            export_data["results"].append(export_result)
        
        with open(file_path, 'w') as f:
            json.dump(export_data, f, indent=2)
    
    def export_csv(self, file_path):
        import csv
        
        with open(file_path, 'w', newline='') as csvfile:
            fieldnames = ['Timestamp', 'Endpoint', 'Algorithm', 'Location', 'Issues', 'Severity']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for result in self.burp_extender.analyzed_jwts:
                issues_summary = "; ".join(["{}: {}".format(issue["severity"], issue["type"]) for issue in result["issues"]])
                severity = self.burp_extender.get_highest_severity(result["issues"])
                
                writer.writerow({
                    'Timestamp': result["timestamp"],
                    'Endpoint': result["endpoint"],
                    'Algorithm': result["header"].get("alg", "Unknown"),
                    'Location': result["location"],
                    'Issues': issues_summary,
                    'Severity': severity
                })

class ClearActionListener(ActionListener):
    
    def __init__(self, burp_extender):
        self.burp_extender = burp_extender
    
    def actionPerformed(self, event):
        result = JOptionPane.showConfirmDialog(
            None, 
            "Are you sure you want to clear all JWT analysis results?",
            "Confirm Clear",
            JOptionPane.YES_NO_OPTION
        )
        
        if result == JOptionPane.YES_OPTION:
            self.burp_extender.analyzed_jwts = []
            self.burp_extender.jwt_cache = {}
            self.burp_extender.jwt_history = defaultdict(list)
            self.burp_extender.table_model.setRowCount(0)
            self.burp_extender.header_text.setText("")
            self.burp_extender.payload_text.setText("")
            self.burp_extender.issues_text.setText("")
            self.burp_extender.activity_text.setText("")
            self.burp_extender.update_statistics()

class SaveConfigActionListener(ActionListener):
    
    def __init__(self, burp_extender):
        self.burp_extender = burp_extender
    
    def actionPerformed(self, event):
        try:
            self.burp_extender.config["check_alg_none"] = self.burp_extender.check_alg_none.isSelected()
            self.burp_extender.config["check_expired"] = self.burp_extender.check_expired.isSelected()
            self.burp_extender.config["check_weak_algorithms"] = self.burp_extender.check_weak_alg.isSelected()
            self.burp_extender.config["check_sensitive_claims"] = self.burp_extender.check_sensitive.isSelected()
            claims_text = self.burp_extender.sensitive_claims_field.getText()
            self.burp_extender.sensitive_claims = [claim.strip() for claim in claims_text.split(",") if claim.strip()]
            
            JOptionPane.showMessageDialog(None, "Configuration saved successfully!")
            
        except Exception as e:
            JOptionPane.showMessageDialog(None, "Error saving configuration: {}".format(str(e)))

class JWTAnalysisEngine:
    
    def __init__(self):
        self.jwks_cache = {}
        self.suspicious_patterns = {
            "email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            "credit_card": re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
            "api_key": re.compile(r'\b[A-Za-z0-9]{32,}\b'),
            "phone": re.compile(r'\b\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b')
        }
    
    def analyze_advanced_vulnerabilities(self, parsed_jwt, jwt_data):
        issues = []
        header = parsed_jwt["header"]
        payload = parsed_jwt["payload"]
        issues.extend(self.check_jwt_confusion(header))
        issues.extend(self.check_timing_vulnerabilities(payload))
        issues.extend(self.check_injection_vulnerabilities(header, payload))
        issues.extend(self.check_crypto_issues(header, payload))
        issues.extend(self.check_privacy_issues(payload))
        
        return issues
    
    def check_jwt_confusion(self, header):
        issues = []
        alg = header.get("alg", "").upper()
        if alg in ["RS256", "RS384", "RS512"]:
            issues.append({
                "severity": "Medium",
                "type": "Potential Algorithm Confusion",
                "description": "JWT uses asymmetric algorithm {}. Verify server doesn't accept symmetric variants.".format(alg),
                "recommendation": "Ensure server strictly validates algorithm and rejects HS256 when expecting RS256"
            })
        if "alg" not in header:
            issues.append({
                "severity": "High",
                "type": "Missing Algorithm",
                "description": "JWT header missing 'alg' parameter",
                "recommendation": "Always specify and validate the algorithm parameter"
            })
        
        return issues
    
    def check_timing_vulnerabilities(self, payload):
        issues = []
        if "exp" in payload and "iat" in payload:
            try:
                exp_time = int(payload["exp"])
                iat_time = int(payload["iat"])
                duration = exp_time - iat_time
                if duration > 86400:
                    hours = duration // 3600
                    issues.append({
                        "severity": "Medium",
                        "type": "Long Token Validity",
                        "description": "JWT is valid for {} hours".format(hours),
                        "recommendation": "Use shorter token validity periods and implement refresh tokens"
                    })
            except (ValueError, TypeError):
                pass
        if "exp" not in payload:
            issues.append({
                "severity": "High",
                "type": "Missing Expiration",
                "description": "JWT does not include expiration claim (exp)",
                "recommendation": "Always include expiration time in JWTs"
            })
        
        return issues
    
    def check_injection_vulnerabilities(self, header, payload):
        issues = []
        if "kid" in header:
            kid_value = str(header["kid"])
            injection_patterns = ["'", '"', "<", ">", "&", "|", ";", "$", "`"]
            
            for pattern in injection_patterns:
                if pattern in kid_value:
                    issues.append({
                        "severity": "High",
                        "type": "Potential Injection in kid",
                        "description": "JWT 'kid' parameter contains suspicious character: {}".format(pattern),
                        "recommendation": "Sanitize and validate 'kid' parameter to prevent injection attacks"
                    })
                    break
        if "jku" in header:
            jku_value = str(header["jku"])
            if jku_value.startswith(("http://", "https://", "ftp://", "file://")):
                issues.append({
                    "severity": "Critical",
                    "type": "Remote JWK Set Reference",
                    "description": "JWT references remote JWK set: {}".format(jku_value),
                    "recommendation": "Avoid remote JWK references or whitelist allowed URLs"
                })
        
        return issues
    
    def check_crypto_issues(self, header, payload):
        issues = []
        if "alg" in header:
            alg = header["alg"].upper()
            if alg in ["HS1", "RS1", "PS1"]:
                issues.append({
                    "severity": "High",
                    "type": "Deprecated Algorithm",
                    "description": "JWT uses deprecated algorithm: {}".format(alg),
                    "recommendation": "Use modern algorithms like HS256, RS256, or ES256"
                })
            standard_algs = ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "NONE"]
            if alg not in standard_algs:
                issues.append({
                    "severity": "Medium",
                    "type": "Non-Standard Algorithm",
                    "description": "JWT uses non-standard algorithm: {}".format(alg),
                    "recommendation": "Use standard JWT algorithms for better security and interoperability"
                })
        
        return issues
    
    def check_privacy_issues(self, payload):
        issues = []
        for claim_name, claim_value in payload.items():
            if isinstance(claim_value, (str, unicode if 'unicode' in dir(__builtins__) else str)):
                if self.suspicious_patterns["email"].search(str(claim_value)):
                    issues.append({
                        "severity": "Medium",
                        "type": "Email Address Exposure",
                        "description": "Claim '{}' contains email address".format(claim_name),
                        "recommendation": "Avoid exposing email addresses in JWT claims or use hashed values"
                    })
                if self.suspicious_patterns["credit_card"].search(str(claim_value)):
                    issues.append({
                        "severity": "Critical",
                        "type": "Credit Card Exposure",
                        "description": "Claim '{}' may contain credit card number".format(claim_name),
                        "recommendation": "Never include credit card numbers in JWT claims"
                    })
                if self.suspicious_patterns["api_key"].search(str(claim_value)):
                    issues.append({
                        "severity": "High",
                        "type": "API Key Exposure",
                        "description": "Claim '{}' may contain API key".format(claim_name),
                        "recommendation": "Avoid including API keys in JWT claims"
                    })
        if len(payload) > 20:
            issues.append({
                "severity": "Low",
                "type": "Excessive Claims",
                "description": "JWT contains {} claims which may increase token size".format(len(payload)),
                "recommendation": "Keep JWT payload minimal to reduce token size and improve performance"
            })
        
        return issues

class JWKSAnalyzer:
    
    def __init__(self):
        self.jwks_cache = {}
    
    def analyze_jwks_issues(self, header, base_url):
        issues = []
        if "jku" in header:
            jku_url = header["jku"]
            issues.extend(self.check_jku_security(jku_url, base_url))
        if "jwk" in header:
            issues.append({
                "severity": "Medium",
                "type": "Embedded JWK",
                "description": "JWT includes embedded JWK in header",
                "recommendation": "Avoid embedding JWKs in JWT headers; use pre-shared keys or JWKS endpoints"
            })
        if "x5u" in header:
            issues.append({
                "severity": "Medium",
                "type": "X.509 Certificate URL",
                "description": "JWT references X.509 certificate URL",
                "recommendation": "Ensure X.509 certificate URLs are whitelisted and validated"
            })
        
        return issues
    
    def check_jku_security(self, jku_url, base_url):
        issues = []
        if jku_url.startswith("http://"):
            issues.append({
                "severity": "High",
                "type": "Insecure JWK Set URL",
                "description": "JWK Set URL uses HTTP instead of HTTPS",
                "recommendation": "Use HTTPS for JWK Set URLs to prevent man-in-the-middle attacks"
            })
        try:
            from urlparse import urlparse
        except ImportError:
            from urllib.parse import urlparse
            
        jku_parsed = urlparse(jku_url)
        base_parsed = urlparse(base_url)
        
        if jku_parsed.netloc != base_parsed.netloc:
            issues.append({
                "severity": "Critical",
                "type": "External JWK Set URL",
                "description": "JWK Set URL points to external domain: {}".format(jku_parsed.netloc),
                "recommendation": "Whitelist allowed JWK Set domains or use same-origin policy"
            })
        
        return issues

class EnhancedJWTAnalyzer:
    
    def __init__(self):
        self.analysis_engine = JWTAnalysisEngine()
        self.jwks_analyzer = JWKSAnalyzer()
    
    def comprehensive_analysis(self, parsed_jwt, jwt_data):
        all_issues = []
        all_issues.extend(self.basic_vulnerability_checks(parsed_jwt, jwt_data))
        all_issues.extend(self.analysis_engine.analyze_advanced_vulnerabilities(parsed_jwt, jwt_data))
        all_issues.extend(self.jwks_analyzer.analyze_jwks_issues(parsed_jwt["header"], jwt_data.get("url", "")))
        unique_issues = []
        seen_types = set()
        for issue in all_issues:
            if issue["type"] not in seen_types:
                unique_issues.append(issue)
                seen_types.add(issue["type"])
        
        return unique_issues
    
    def basic_vulnerability_checks(self, parsed_jwt, jwt_data):
        issues = []
        header = parsed_jwt["header"]
        payload = parsed_jwt["payload"]
        if header.get("alg", "").lower() == "none":
            issues.append({
                "severity": "Critical",
                "type": "Algorithm None",
                "description": "JWT uses 'alg: none' allowing token forgery",
                "recommendation": "Use a secure signing algorithm like RS256 or HS256"
            })
        if "exp" in payload:
            try:
                exp_time = int(payload["exp"])
                if exp_time < time.time():
                    issues.append({
                        "severity": "High",
                        "type": "Expired Token",
                        "description": "JWT has expired",
                        "recommendation": "Implement proper token expiration validation"
                    })
            except (ValueError, TypeError):
                issues.append({
                    "severity": "Medium",
                    "type": "Invalid Expiration",
                    "description": "JWT expiration claim is not a valid timestamp",
                    "recommendation": "Ensure expiration claim uses valid Unix timestamp"
                })
        
        return issues

class ConfigurationManager:
    
    def __init__(self):
        self.default_config = {
            "check_alg_none": True,
            "check_expired": True,
            "check_weak_algorithms": True,
            "check_sensitive_claims": True,
            "check_missing_kid": True,
            "check_jwks_issues": True,
            "verbosity": "medium",
            "auto_fetch_jwks": False,
            "max_token_age_hours": 24,
            "sensitive_claims": [
                "email", "username", "password", "admin", "role", 
                "permissions", "phone", "address", "ssn", "credit_card"
            ]
        }
    
    def get_config(self):
        return self.default_config.copy()
    
    def update_config(self, new_config):
        self.default_config.update(new_config)
    
    def export_config(self, file_path):
        with open(file_path, 'w') as f:
            json.dump(self.default_config, f, indent=2)
    
    def import_config(self, file_path):
        try:
            with open(file_path, 'r') as f:
                imported_config = json.load(f)
                self.default_config.update(imported_config)
            return True
        except Exception as e:
            print("[!] Error importing configuration: {}".format(str(e)))
            return False
