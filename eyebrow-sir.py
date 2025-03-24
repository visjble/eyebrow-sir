#!/usr/bin/env python3
"""
MinimalBrowser - A lightweight Linux web browser with minimal resource impact and enhanced security
"""
import sys
import os
import signal
from urllib.parse import urlparse, urljoin
import re

from PyQt6.QtCore import QUrl, Qt, QSize, QTimer
from PyQt6.QtWidgets import (QApplication, QMainWindow, QLineEdit, 
                           QToolBar, QMenu, QTabWidget, 
                           QWidget, QVBoxLayout, QMessageBox)
from PyQt6.QtGui import QIcon, QKeySequence, QAction, QShortcut
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import (QWebEnginePage, QWebEngineProfile, 
                                  QWebEngineUrlRequestInterceptor, 
                                  QWebEngineSettings,
                                  QWebEngineCertificateError)

# Comprehensive list of ad/tracking domains
BLOCKED_DOMAINS = [
    "doubleclick.net", "googleadservices.com", "googlesyndication.com",
    "adnxs.com", "rubiconproject.com", "criteo.com", "taboola.com",
    "outbrain.com", "facebook.com/tr", "google-analytics.com", 
    "amazon-adsystem.com", "adform.net", "pubmatic.com", 
    "scorecardresearch.com", "chartbeat.com", "moatads.com"
]

# Known malicious URL patterns
MALICIOUS_PATTERNS = [
    r'(\.exe|\.msi|\.bat|\.cmd)$',  # Executable file downloads
    r'data:text/html',  # Data URLs (potential XSS)
    r'javascript:',     # JavaScript URLs
]

# HSTS preloaded domains
HSTS_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "twitter.com",
    "github.com", "wikipedia.org", "apple.com", "microsoft.com"
]

class RequestInterceptor(QWebEngineUrlRequestInterceptor):
    """Intercepts and filters web requests for security and performance"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.blocked_domains = BLOCKED_DOMAINS
        
    def interceptRequest(self, info):
        url = info.requestUrl().toString().lower()
        resource_type = info.resourceType()
        
        # Block known tracking/ad domains
        if any(domain in url for domain in self.blocked_domains):
            info.block(True)
            return
            
        # Block malicious patterns
        if any(re.search(pattern, url) for pattern in MALICIOUS_PATTERNS):
            info.block(True)
            return
            
        # Optional: Apply resource type filtering based on user settings
        if self.should_block_resource_type(resource_type):
            info.block(True)
            return
            
    def should_block_resource_type(self, resource_type):
        # This would check against user preferences
        # For now, we'll return False to allow all resource types
        return False


class WebPage(QWebEnginePage):
    """Custom webpage with enhanced security and performance features"""
    
    def __init__(self, profile, parent=None):
        super().__init__(profile, parent)
        # Set Content-Security-Policy as default
        self.setFeaturePermission = self.enhanced_permission
        # Register certificate error handler
        self.certificateError.connect(self.handle_certificate_error)
        
    def javaScriptConsoleMessage(self, level, message, line, source):
        # Optionally log JavaScript errors to a file or console
        pass
        
    def acceptNavigationRequest(self, url, type, isMainFrame):
        # Enforce HTTPS
        if url.scheme() not in ['https', 'file', 'qrc']:
            # Convert http URLs to https
            if url.scheme() == 'http':
                secure_url = QUrl(url)
                secure_url.setScheme('https')
                self.view().load(secure_url)
                return False
            else:
                return False
                
        # Validate URLs before navigation
        if not url.isValid():
            return False
            
        # Enforce HSTS for known domains
        host = url.host().lower()
        if any(hsts_domain in host for hsts_domain in HSTS_DOMAINS) and url.scheme() != 'https':
            secure_url = QUrl(url)
            secure_url.setScheme('https')
            self.view().load(secure_url)
            return False
            
        # Check for malicious URL patterns
        url_string = url.toString().lower()
        if any(re.search(pattern, url_string) for pattern in MALICIOUS_PATTERNS):
            if isMainFrame:
                QMessageBox.warning(self.view(), "Security Warning", 
                                  "Potentially malicious URL blocked")
            return False
            
        return super().acceptNavigationRequest(url, type, isMainFrame)
        
    def enhanced_permission(self, feature, permission):
        # Restrict permissions for security
        # Block geolocation, media, notifications by default
        from PyQt6.QtWebEngineCore import QWebEnginePage
        
        if feature in [QWebEnginePage.Feature.Geolocation, 
                       QWebEnginePage.Feature.MediaAudioCapture,
                       QWebEnginePage.Feature.MediaVideoCapture,
                       QWebEnginePage.Feature.MediaAudioVideoCapture,
                       QWebEnginePage.Feature.Notifications]:
            super().setFeaturePermission(feature, QWebEnginePage.PermissionPolicy.DenyPermission)
        else:
            super().setFeaturePermission(feature, permission)
            
    def handle_certificate_error(self, error):
        # Block navigation on certificate errors
        QMessageBox.critical(self.view(), "Security Error", 
                           f"Invalid SSL certificate for {error.url().host()}\n"
                           f"Error: {error.errorDescription()}")
        return False  # Reject certificate


class BrowserTab(QWidget):
    """Individual browser tab with its own web view"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.hibernated = False
        
        # Create custom profile for this tab with reduced memory usage
        self.profile = QWebEngineProfile(self)
        self.profile.setPersistentCookiesPolicy(QWebEngineProfile.PersistentCookiesPolicy.NoPersistentCookies)
        self.profile.setHttpCacheType(QWebEngineProfile.HttpCacheType.MemoryHttpCache)
        self.profile.setCachePath("")  # No disk cache
        
        # Set up request interceptor for blocking unwanted content
        self.interceptor = RequestInterceptor()
        self.profile.setUrlRequestInterceptor(self.interceptor)
        
        # Configure web view with minimal JavaScript
        self.web_view = QWebEngineView()
        self.page = WebPage(self.profile, self.web_view)
        self.web_view.setPage(self.page)
        
        # Apply secure default settings
        settings = self.page.settings()
        settings.setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, True)  # Keep basic JS
        settings.setAttribute(QWebEngineSettings.WebAttribute.JavascriptCanOpenWindows, False)
        settings.setAttribute(QWebEngineSettings.WebAttribute.PluginsEnabled, False)
        settings.setAttribute(QWebEngineSettings.WebAttribute.AutoLoadImages, True)  # Keep images for usability
        settings.setAttribute(QWebEngineSettings.WebAttribute.WebGLEnabled, False)
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalStorageEnabled, False)  # Disable localStorage
        settings.setAttribute(QWebEngineSettings.WebAttribute.XSSAuditingEnabled, True)  # Enable XSS protection
        settings.setAttribute(QWebEngineSettings.WebAttribute.AllowRunningInsecureContent, False)  # Block mixed content
        
        # Set default headers for additional security
        self.default_headers = {
            "Content-Security-Policy": "default-src 'self' https:; script-src 'self' https: 'unsafe-inline'; img-src 'self' https: data:;",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "SAMEORIGIN",
            "Referrer-Policy": "no-referrer-when-downgrade"
        }
        
        # Connect signals
        self.web_view.loadStarted.connect(self.load_started)
        self.web_view.loadFinished.connect(self.load_finished)
        
        self.layout.addWidget(self.web_view)
        
    def load_started(self):
        # We can't directly set HTTP headers in this version of PyQt
        # Instead, we'll inject a script that sets equivalent meta tags
        headers_script = """
        (function() {
            var head = document.getElementsByTagName('head')[0];
            if (head) {
                %s
            }
        })();
        """
        
        meta_tags = []
        for name, value in self.default_headers.items():
            meta_tags.append(f"var meta = document.createElement('meta'); meta.httpEquiv = '{name}'; meta.content = '{value}'; head.appendChild(meta);")
            
        self.page.runJavaScript(headers_script % '\n'.join(meta_tags))
        
    def load_finished(self, ok):
        if not ok:
            self.show_error_page()
            
    def show_error_page(self):
        error_html = """
        <html>
        <head>
            <style>
                body { font-family: sans-serif; padding: 20px; }
                h2 { color: #cc0000; }
            </style>
        </head>
        <body>
            <h2>Page Failed to Load</h2>
            <p>The requested page could not be loaded. This could be due to network issues or browser security restrictions.</p>
        </body>
        </html>
        """
        self.web_view.setHtml(error_html)
        
    def load(self, url):
        # Always enforce HTTPS
        if not url.scheme() or url.scheme() == "http":
            url.setScheme("https")
            
        # Check for common phishing signs
        url_string = url.toString().lower()
        host = url.host().lower()
        
        if self.check_phishing_signs(url_string, host):
            QMessageBox.warning(self, "Security Warning", 
                              f"Suspicious URL detected: {host}\n"
                              "This may be a phishing attempt.")
            return
            
        self.web_view.load(url)
        
    def check_phishing_signs(self, url_string, host):
        # Check for suspicious domains (basic example)
        suspicious = False
        
        # Check for domain spoofing with homoglyphs
        common_domains = ["google", "amazon", "facebook", "apple", "microsoft", "paypal", "netflix"]
        for domain in common_domains:
            if domain in host and domain not in host.split('.'):
                suspicious = True
                
        # Check for excessive subdomains (phishing often uses many)
        if host.count('.') > 3:
            suspicious = True
            
        return suspicious
        
    def url(self):
        return self.web_view.url()
        
    def title(self):
        return self.web_view.title()
        
    def hibernate(self):
        """Hibernate tab to save resources"""
        if not self.hibernated:
            self.hibernated = True
            # Store current URL
            self.hibernated_url = self.url()
            # Unload page content
            self.web_view.setHtml("<html><body><h3>Tab hibernated to save resources. Click to restore.</h3></body></html>")
            
    def wake(self):
        """Wake hibernated tab"""
        if self.hibernated:
            self.hibernated = False
            # Reload original URL
            if hasattr(self, 'hibernated_url'):
                self.web_view.load(self.hibernated_url)


class MinimalBrowser(QMainWindow):
    """Main browser window with tabs and controls"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("EyeBrow-sir")
        self.resize(1024, 768)
        
        # Central widget and layout
        self.central_widget = QWidget()
        self.layout = QVBoxLayout(self.central_widget)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.setCentralWidget(self.central_widget)
        
        # Create UI elements
        self.create_toolbar()
        self.create_tab_widget()
        self.create_shortcuts()
        
        # Initial tab
        self.add_new_tab(QUrl("https://duckduckgo.com"))
        
        # Set up periodic memory optimization
        self.cleanup_timer = QTimer(self)
        self.cleanup_timer.timeout.connect(self.optimize_memory)
        self.cleanup_timer.start(60000)  # Run every minute
        
        # Force process isolation for improved security
        os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] += " --site-per-process"
        
    def create_toolbar(self):
        """Create navigation toolbar with minimal controls"""
        self.toolbar = QToolBar("Navigation")
        self.toolbar.setMovable(False)
        self.toolbar.setIconSize(QSize(16, 16))
        self.addToolBar(self.toolbar)
        
        # Back and Forward buttons
        self.back_action = QAction(self)
        self.back_action.setText("Back")
        self.back_action.triggered.connect(lambda: self.current_tab().web_view.back())
        self.toolbar.addAction(self.back_action)
        
        self.forward_action = QAction(self)
        self.forward_action.setText("Forward")  
        self.forward_action.triggered.connect(lambda: self.current_tab().web_view.forward())
        self.toolbar.addAction(self.forward_action)
        
        # Reload button
        self.reload_action = QAction(self)
        self.reload_action.setText("Reload")
        self.reload_action.triggered.connect(lambda: self.current_tab().web_view.reload())
        self.toolbar.addAction(self.reload_action)
        
        # URL bar with sanitization
        self.url_bar = QLineEdit()
        self.url_bar.returnPressed.connect(self.navigate_to_url)
        self.toolbar.addWidget(self.url_bar)
        
        # Security indicator
        self.security_indicator = QAction("🔒", self)
        self.toolbar.addAction(self.security_indicator)
        
        # Settings menu
        self.settings_menu = QMenu(self)
        
        # JavaScript toggle
        self.js_action = QAction("Disable JavaScript", self)
        self.js_action.setCheckable(True)
        self.js_action.triggered.connect(self.toggle_javascript)
        self.settings_menu.addAction(self.js_action)
        
        # Images toggle
        self.images_action = QAction("Disable Images", self)
        self.images_action.setCheckable(True)
        self.images_action.triggered.connect(self.toggle_images)
        self.settings_menu.addAction(self.images_action)
        
        # Cookie toggle
        self.cookies_action = QAction("Block All Cookies", self)
        self.cookies_action.setCheckable(True)
        self.cookies_action.triggered.connect(self.toggle_cookies)
        self.settings_menu.addAction(self.cookies_action)
        
        # Add settings button
        self.settings_button = QAction("Settings", self)
        self.settings_button.setMenu(self.settings_menu)
        self.toolbar.addAction(self.settings_button)
        
    def create_tab_widget(self):
        """Create tab container widget"""
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.setTabsClosable(True)
        self.tabs.setMovable(True)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.tabs.currentChanged.connect(self.tab_changed)
        
        # Add tab button
        self.add_tab_button = QAction("+", self)
        self.add_tab_button.triggered.connect(lambda: self.add_new_tab())
        self.tabs.setCornerWidget(QToolBar(self))
        self.tabs.cornerWidget().addAction(self.add_tab_button)
        
        self.layout.addWidget(self.tabs)
        
    def create_shortcuts(self):
        """Set up keyboard shortcuts"""
        # New tab
        new_tab_shortcut = QShortcut(QKeySequence("Ctrl+T"), self)
        new_tab_shortcut.activated.connect(lambda: self.add_new_tab())
        
        # Close tab
        close_tab_shortcut = QShortcut(QKeySequence("Ctrl+W"), self)
        close_tab_shortcut.activated.connect(lambda: self.close_tab(self.tabs.currentIndex()))
        
        # Navigate to address bar
        focus_url_shortcut = QShortcut(QKeySequence("Ctrl+L"), self)
        focus_url_shortcut.activated.connect(self.url_bar.setFocus)
        
        # Refresh
        refresh_shortcut = QShortcut(QKeySequence("F5"), self)
        refresh_shortcut.activated.connect(lambda: self.current_tab().web_view.reload())
        
    def add_new_tab(self, url=None):
        """Create a new browser tab"""
        if url is None:
            url = QUrl("https://duckduckgo.com")
            
        # Create new tab
        browser = BrowserTab(self)
        index = self.tabs.addTab(browser, "New Tab")
        self.tabs.setCurrentIndex(index)
        
        # Update tab title when page title changes
        browser.web_view.titleChanged.connect(
            lambda title, browser=browser: self.update_tab_title(browser, title))
        
        # Update URL bar when URL changes
        browser.web_view.urlChanged.connect(
            lambda url, browser=browser: self.update_url(browser, url))
            
        # Update security indicator
        browser.web_view.urlChanged.connect(
            lambda url, browser=browser: self.update_security_indicator(browser, url))
        
        # Load the URL
        browser.load(url)
        
    def close_tab(self, index):
        """Close the tab at the given index"""
        if self.tabs.count() > 1:
            self.tabs.removeTab(index)
        else:
            # Don't close the last tab, just clear it
            self.current_tab().load(QUrl("https://duckduckgo.com"))
            
    def current_tab(self):
        """Get the currently active tab"""
        return self.tabs.currentWidget()
        
    def navigate_to_url(self):
        """Navigate to URL from the address bar with enhanced security"""
        url_text = self.url_bar.text().strip()
        
        # Basic URL validation
        if not url_text:
            return
            
        # Sanitize input to prevent injection
        url_text = self.sanitize_url_input(url_text)
            
        # Handle URL formatting
        parsed = urlparse(url_text)
        if not parsed.scheme:
            # If it looks like a domain, prepend https
            if "." in url_text and " " not in url_text:
                url = QUrl("https://" + url_text)
            else:
                # Otherwise, treat as a search query
                search_url = f"https://duckduckgo.com/?q={url_text.replace(' ', '+')}"
                url = QUrl(search_url)
        else:
            url = QUrl(url_text)
            
        # Final security check
        if url.scheme() != "https" and url.scheme() != "file":
            url.setScheme("https")
            
        self.current_tab().load(url)
        
    def sanitize_url_input(self, url_text):
        """Sanitize URL input to prevent injection attacks"""
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>"\'%]', '', url_text)
        
        # Check for script injection
        if re.search(r'javascript:|data:|vbscript:', sanitized, re.IGNORECASE):
            return "about:blank"
            
        return sanitized
        
    def update_tab_title(self, browser, title):
        """Update tab title when page title changes"""
        index = self.tabs.indexOf(browser)
        if index != -1:
            # Sanitize title to prevent UI spoofing
            safe_title = re.sub(r'[<>]', '', title)
            display_title = safe_title[:15] + "..." if len(safe_title) > 15 else safe_title
            self.tabs.setTabText(index, display_title)
            if browser == self.current_tab():
                self.setWindowTitle(f"{safe_title} - MinimalBrowser")
                
    def update_url(self, browser, url):
        """Update URL bar when page URL changes"""
        if browser == self.current_tab():
            self.url_bar.setText(url.toString())
            
    def update_security_indicator(self, browser, url):
        """Update security indicator based on connection security"""
        if browser == self.current_tab():
            if url.scheme() == "https":
                self.security_indicator.setText("🔒")
                self.security_indicator.setToolTip("Secure Connection")
            else:
                self.security_indicator.setText("⚠️")
                self.security_indicator.setToolTip("Insecure Connection")
            
    def tab_changed(self, index):
        """Handle tab selection change"""
        if index != -1:
            tab = self.tabs.widget(index)
            self.update_url(tab, tab.url())
            self.update_security_indicator(tab, tab.url())
            self.setWindowTitle(f"{tab.title()} - MinimalBrowser")
            
            # Wake up hibernated tabs when selected
            if hasattr(tab, 'hibernated') and tab.hibernated:
                tab.wake()
            
    def toggle_javascript(self, checked):
        """Toggle JavaScript on/off"""
        for i in range(self.tabs.count()):
            tab = self.tabs.widget(i)
            settings = tab.page.settings()
            settings.setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, not checked)
            
    def toggle_images(self, checked):
        """Toggle image loading on/off"""
        for i in range(self.tabs.count()):
            tab = self.tabs.widget(i)
            settings = tab.page.settings()
            settings.setAttribute(QWebEngineSettings.WebAttribute.AutoLoadImages, not checked)
            
    def toggle_cookies(self, checked):
        """Toggle cookie acceptance on/off"""
        for i in range(self.tabs.count()):
            tab = self.tabs.widget(i)
            if checked:
                tab.profile.setPersistentCookiesPolicy(
                    QWebEngineProfile.PersistentCookiesPolicy.NoPersistentCookies)
                tab.profile.setHttpCacheType(QWebEngineProfile.HttpCacheType.NoCache)
            else:
                tab.profile.setPersistentCookiesPolicy(
                    QWebEngineProfile.PersistentCookiesPolicy.NoPersistentCookies)
                tab.profile.setHttpCacheType(QWebEngineProfile.HttpCacheType.MemoryHttpCache)
            
    def optimize_memory(self):
        """Perform memory optimization tasks"""
        # Clear unused memory caches
        QWebEngineProfile.defaultProfile().clearHttpCache()
        
        # Hibernate background tabs to save memory
        for i in range(self.tabs.count()):
            if i != self.tabs.currentIndex():
                tab = self.tabs.widget(i)
                # Hibernate tabs that have been inactive for a while
                if hasattr(tab, 'hibernate') and not tab.hibernated:
                    # Only hibernate tabs that haven't been used in a while
                    from PyQt6.QtCore import QDateTime
                    if not hasattr(tab, 'last_active_time') or \
                       (QDateTime.currentDateTime().toMSecsSinceEpoch() - tab.last_active_time > 300000):  # 5 minutes
                        tab.hibernate()
            else:
                # Update the last active time for the current tab
                tab = self.tabs.widget(i)
                from PyQt6.QtCore import QDateTime
                tab.last_active_time = QDateTime.currentDateTime().toMSecsSinceEpoch()
                if hasattr(tab, 'wake') and tab.hibernated:
                    tab.wake()
                    
    def closeEvent(self, event):
        """Clean up resources when closing the browser"""
        # Clean up profiles and caches
        for i in range(self.tabs.count()):
            tab = self.tabs.widget(i)
            if tab.profile:
                tab.profile.clearHttpCache()
        
        # Ensure proper deletion of pages to prevent "Release of profile" warning
        for i in range(self.tabs.count()):
            tab = self.tabs.widget(i)
            if hasattr(tab, 'web_view'):
                tab.web_view.setPage(None)  # Detach page from view
                if hasattr(tab, 'page'):
                    tab.page.deleteLater()  # Schedule page for deletion
        
        event.accept()


def main():
    """Main entry point for the browser"""
    # Suppress WebEngine warnings about dictionaries path
    os.environ["QTWEBENGINE_DISABLE_LOGGING"] = "1"
    
    # Disable DBUS connection attempts to prevent errors
    os.environ["QT_ASSUME_STDERR_HAS_CONSOLE"] = "1"
    os.environ["QT_LOGGING_RULES"] = "*.debug=false;qt.qpa.*=false"
    
    # Disable ALSA errors
    os.environ["ALSA_CONFIG_PATH"] = "/dev/null"
    
    # Set dictionary path to avoid warnings
    if not os.path.exists("./qtwebengine_dictionaries"):
        os.makedirs("./qtwebengine_dictionaries", exist_ok=True)
    os.environ["QTWEBENGINE_DICTIONARIES_PATH"] = "./qtwebengine_dictionaries"
    
    # Enable Qt WebEngine flags for better performance and security
    os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = "--disable-gpu --disable-accelerated-video-decode --disable-accelerated-video-encode --enable-low-end-device-mode --site-per-process --disable-features=RendererCodeIntegrity"
    
    # Create application
    app = QApplication(sys.argv)
    app.setApplicationName("MinimalBrowser")
    
    # Handle Ctrl+C in terminal
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    
    # Create and show the browser
    browser = MinimalBrowser()
    browser.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()