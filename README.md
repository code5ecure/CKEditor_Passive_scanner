# CKEditor Passive Scanner (Burp Suite Extension)

![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Professional%20%2F%20Community-orange)
![API](https://img.shields.io/badge/API-Montoya%20(v1.0)-blue)
![Java](https://img.shields.io/badge/Java-17%2B-red)

A lightweight, passive scanning extension for **Burp Suite** designed to detect, classify, and report CKEditor installations (versions 4.x and 5.x) and their plugins. 

Built using the modern **Montoya API**, this extension helps security researchers identify potentially vulnerable WYSIWYG editors without sending active scan payloads.

---
![Alt Text]()

## 🚀 Key Features

* **Passive Detection:** Identifies CKEditor via HTTP response bodies (JavaScript, CSS, HTML markers, and `CKEDITOR.version` variables).
* **Version Fingerprinting:** Extracts exact version numbers for CKEditor 4 and detects CKEditor 5 build types (Classic, Inline, Balloon).
* **Plugin Discovery:** Passively enumerates installed plugins (e.g., file uploaders, KCFinder) by analyzing resource paths.
* **Smart Issue Reporting:** Automatically generates **Information** severity issues in the Burp Dashboard with detailed evidence.

## 📥 Installation

1.  **Download:** Get the latest JAR file from the [Releases](../../releases) page.
2.  **Load in Burp:**
    * Open **Burp Suite**.
    * Go to **Extensions** -> **Installed**.
    * Click **Add**.
    * Select **Java** and choose the `CKEditorPassiveScanner.jar` file.
3.  **Verify:** You should see a new tab labeled **CKEditor Scanner** in the Burp UI.

## 🛠 Usage

1.  **Browse:** Simply browse your target application through Burp Proxy.
2.  **Monitor:** Check the **CKEditor Scanner** tab. It will populate a table whenever CKEditor assets are detected.
3.  **Analyze:**
    * Click a row to view the request/response details.
    * Right-click a row to **Send to Repeater**.
    * Check the **Target > Site Map** or **Dashboard** for formal issues labeled "CKEditor Detected".

## 🔍 How It Works

The extension implements the `HttpHandler` interface to passively inspect `HttpResponseReceived` events. It uses regex signatures to find:
* `CKEDITOR.version` variables.
* Specific CSS/JS file naming conventions.
* `data-ckeditor-*` HTML attributes.
* Directory structures typical of CKEditor deployments (e.g., `/assets/plugins/`).

*No payloads are sent to the server. All detection is performed on traffic that is already flowing through the proxy.*

## 🏗 Build from Source

Requirements:
* Java JDK 17+
* Maven or Gradle

```bash
git clone [https://github.com/yourusername/ckeditor-passive-scanner.git](https://github.com/yourusername/ckeditor-passive-scanner.git)
cd ckeditor-passive-scanner
# If using Gradle
./gradlew build
# The jar will be in build/libs/

if u are in windows:

just execute this:
javac -d build -cp burpsuite_pro_v2025.10.4.jar CKEditorPassiveScanner.java
jar cf CKEditorPassiveScanner.jar -C build .

🤝 Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

🗺️ Roadmap & Future Works
We are looking to expand the capabilities of this extension beyond CKEditor to become a comprehensive editor auditing suite.

1. Multi-Editor Support
Wysiwyg Expansion: Add passive detection signatures for other popular editors:

TinyMCE (Version detection and plugin mapping)

Froala (License check and versioning)

Summernote

Quill / Trix

2. Interesting Path Discovery
Automatic Endpoint Mapping: Automatically identify hidden management or upload endpoints:

Detecting kcfinder/browse.php

Detecting ckfinder/connector

Locating custom file-browser integration paths.

3. Automatic Security Auditing
Configuration Analysis: Move from passive detection to active security checks:

Check for config.js exposure.

Test for default/weak configurations in file uploaders.

Automated version-based vulnerability (CVE) matching.
📄 License
MIT
