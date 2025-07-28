# Android Static Analyzer

A basic static analysis tool for Android applications developed in Java, capable of identifying common security misconfigurations in `AndroidManifest.xml` and insecure API usages or hardcoded sensitive information within the application's decompiled Java source code. It generates detailed reports in console, JSON, and PDF formats.

## Features

* **Manifest Analysis:**
    * Detects `android:debuggable="true"`.
    * Checks for `android:allowBackup="true"`.
    * Identifies unprotected exported components (Activities, Services, Broadcast Receivers, Content Providers).
    * Flags `android:usesCleartextTraffic="true"`.
* **Code Analysis:**
    * Detects potential hardcoded sensitive information (e.g., API keys, passwords, specific sensitive URLs) in Java source code.
    * Identifies insecure `WebView` configurations (`setJavaScriptEnabled(true)`).
    * Flags potential logging of sensitive data.
* **Reporting:**
    * Outputs analysis summary to the console.
    * Generates a structured JSON report.
    * Generates a user-friendly PDF report.
* **Automated Cleanup:** Automatically deletes temporary decompiled files.

## How It Works

The tool integrates with external open-source tools to perform its analysis:
* **APKTool:** Used for decompiling APKs to extract the `AndroidManifest.xml` and Smali code.
* **JADX:** Used for decompiling Android DEX bytecode into readable Java source code for deeper code analysis.

## Prerequisites

To run this project on your system, you will need:

* **Operating System:** Linux (Ubuntu recommended, or Windows Subsystem for Linux (WSL2)).
* **Java Development Kit (JDK):** Version 17 or higher.
    * Verify with: `java -version`
* **Apache Maven:** Version 3.x.x or higher.
    * Verify with: `mvn --version`
* **Git:** For cloning the repository.
    * Verify with: `git --version`
* **APKTool:** Installed and accessible in your system's PATH.
* **JADX:** Installed and accessible in your system's PATH.

### **Setting up APKTool**

1.  Create the local bin directory and add it to PATH (if not already present):
    ```bash
    mkdir -p ~/.local/bin
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
    source ~/.bashrc
    ```
2.  Download the APKTool wrapper script:
    ```bash
    wget [https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool](https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool) -O ~/.local/bin/apktool
    chmod +x ~/.local/bin/apktool
    ```
3.  Download the latest `apktool.jar` (check [https://ibotpeaches.github.io/Apktool/install/](https://ibotpeaches.github.io/Apktool/install/) for the very latest version link):
    ```bash
    wget [https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar](https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar) -O ~/.local/bin/apktool.jar
    ```
4.  Verify installation: `apktool --version`

### **Setting up JADX**

1.  Go to your Downloads directory: `cd ~/Downloads`
2.  Download the latest JADX release zip file (check [https://github.com/skylot/jadx/releases](https://github.com/skylot/jadx/releases) for the very latest version):
    ```bash
    wget [https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip](https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip)
    ```
3.  Unzip the file: `unzip jadx-1.4.7.zip`
4.  Move the extracted contents to `/opt/jadx`:
    ```bash
    sudo mkdir /opt/jadx
    sudo mv jadx-1.4.7/bin /opt/jadx/
    sudo mv jadx-1.4.7/lib /opt/jadx/
    # You might also want to move LICENSE, NOTICE, README.md if they were extracted directly
    # sudo mv jadx-1.4.7/LICENSE /opt/jadx/
    # sudo mv jadx-1.4.7/NOTICE /opt/jadx/
    # sudo mv jadx-1.4.7/README.md /opt/jadx/
    ```
    *Note: The `unzip` command might extract files directly into `~/Downloads` or into a folder like `jadx-1.4.7` or `jadx`. Adjust the `mv` command if needed based on what `ls -l` shows in your `~/Downloads` directory after unzipping.*
5.  Add JADX to your PATH:
    ```bash
    echo 'export PATH="$PATH:/opt/jadx/bin"' >> ~/.bashrc
    source ~/.bashrc
    ```
6.  Verify installation: `jadx --version`

## Project Setup (Local)

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/YOUR_GITHUB_USERNAME/YOUR_REPO_NAME.git](https://github.com/YOUR_GITHUB_USERNAME/YOUR_REPO_NAME.git)
    cd YOUR_REPO_NAME # e.g., cd AndroidStaticAnalyzer
    ```
    *(Replace `YOUR_GITHUB_USERNAME` and `YOUR_REPO_NAME` with your actual GitHub details.)*

2.  **Build the project (Fat JAR):**
    This command compiles the Java code and packages all dependencies into a single executable JAR file.
    ```bash
    mvn clean install
    ```
    *(Ensure Maven reports `BUILD SUCCESS` and the `maven-shade-plugin` ran, creating a multi-MB JAR in the `target/` directory.)*

## How to Run the Analyzer

Once the project is built, you can run it from the command line by providing the path to an APK file.

1.  **Download a Sample APK:** You can use a deliberately vulnerable APK like OWASP's InsecureBankv2 for testing:
    [https://github.com/OWASP/iGoat-Android/releases](https://github.com/OWASP/iGoat-Android/releases) (Look for `InsecureBankv2.apk`)
    Place it in an accessible location, for example, `~/Downloads/InsecureBankv2.apk`.

2.  **Execute the Analyzer:**
    Navigate to your project's root directory (`cd YOUR_PROJECT_ROOT`) and run:
    ```bash
    java -jar target/android-analyzer-1.0-SNAPSHOT.jar ~/Downloads/InsecureBankv2.apk
    ```
    *(Replace `~/Downloads/InsecureBankv2.apk` with the actual path to your APK.)*

## Output

The tool will provide:
* Console output showing the decompilation process and an analysis summary.
* A JSON report (e.g., `analysis_report_<timestamp>.json`) in the `target/` directory.
* A PDF report (e.g., `analysis_report_<timestamp>.pdf`) in the `target/` directory.

You can open the `.json` file with any text editor and the `.pdf` file with a PDF viewer (like Evince on Ubuntu) to see the detailed structured reports.

## Contribution & Future Work

Feel free to contribute to this project! Ideas for future enhancements include:
* More sophisticated Data Flow / Taint Analysis.
* Integration with static analysis frameworks (Soot, FlowDroid).
* Detection of more insecure API usages (e.g., weak cryptography, insecure data storage).
* Dependency vulnerability scanning.
* An interactive HTML report viewer.
* A web-based interface for analysis.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.