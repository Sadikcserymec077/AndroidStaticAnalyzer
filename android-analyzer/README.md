Android Static Analyzer (Full-Stack Web Application)
A comprehensive static analysis tool for Android applications. This project consists of a Java backend that performs the core analysis and a ReactJS frontend for a user-friendly web interface. It's capable of identifying common security misconfigurations in AndroidManifest.xml and insecure API usages or hardcoded sensitive information within the application's decompiled Java source code. It generates detailed reports in JSON and PDF formats.

Features
Manifest Analysis:

Detects android:debuggable="true".

Checks for android:allowBackup="true".

Identifies unprotected exported components (Activities, Services, Broadcast Receivers, Content Providers).

Flags android:usesCleartextTraffic="true".

Code Analysis:

Detects potential hardcoded sensitive information (e.g., API keys, passwords, specific sensitive URLs) in Java source code.

Identifies insecure WebView configurations (setJavaScriptEnabled(true)).

Flags potential logging of sensitive data.

Detects usage of Weak Cryptographic Algorithms/Modes (e.g., AES/ECB, DES).

Identifies Insecure File Storage Modes (MODE_WORLD_READABLE, MODE_WORLD_WRITABLE).

Flags Insecure Certificate/Hostname Validation bypasses in TLS/SSL.

Detects Hardcoded Cryptographic Keys/IVs/Salts.

Reporting:

Outputs analysis summary to the console (backend).

Generates a structured JSON report.

Generates a professional PDF report.

Web Interface: ReactJS frontend for easy APK upload and report download.

Automated Cleanup: Automatically deletes temporary decompiled files after analysis.

How It Works
The tool integrates with external open-source tools for its core analysis capabilities:

APKTool: Used for decompiling APKs to extract the AndroidManifest.xml and Smali code.

JADX: Used for decompiling Android DEX bytecode into readable Java source code for deeper code analysis.

The architecture is a client-server model:

ReactJS Frontend: Provides the web interface for users to upload APKs.

Java Backend (SparkJava): Receives the uploaded APK, orchestrates APKTool and JADX, performs the static analysis, generates the PDF report, and sends the PDF back to the frontend.

Prerequisites
To run this project locally on your system, you will need:

Operating System: Linux (Ubuntu recommended, or Windows Subsystem for Linux (WSL2)).

Java Development Kit (JDK): Version 17 or higher.

Verify with: java -version

Apache Maven: Version 3.x.x or higher.

Verify with: mvn --version

Node.js and npm: Version 14.x or higher (recommended 16+).

Verify with: node -v and npm -v

Git: For cloning the repository.

Verify with: git --version

APKTool: Installed and accessible in your system's PATH.

JADX: Installed and accessible in your system's PATH.

Setting up APKTool
Create the local bin directory and add it to PATH (if not already present):

mkdir -p ~/.local/bin
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

Download the APKTool wrapper script:

wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -O ~/.local/bin/apktool
chmod +x ~/.local/bin/apktool

Download the latest apktool.jar (check https://ibotpeaches.github.io/Apktool/install/ for the very latest version link, e.g., 2.9.3):

wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar -O ~/.local/bin/apktool.jar

Verify installation: apktool --version

Setting up JADX
Go to your Downloads directory: cd ~/Downloads

Download the latest JADX release zip file (check https://github.com/skylot/jadx/releases for the very latest version, e.g., v1.4.7):

wget https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip

Unzip the file: unzip jadx-1.4.7.zip

Move the extracted contents to /opt/jadx:

sudo mkdir /opt/jadx
# Adjust the source path based on what 'ls -l' shows after unzipping (e.g., 'jadx-1.4.7/bin' or 'jadx/bin')
sudo mv jadx-1.4.7/bin /opt/jadx/
sudo mv jadx-1.4.7/lib /opt/jadx/

Add JADX to your PATH:

echo 'export PATH="$PATH:/opt/jadx/bin"' >> ~/.bashrc
source ~/.bashrc

Verify installation: jadx --version

Setting up Node.js and npm
If not already installed:

sudo apt install nodejs npm -y

Verify installation: node -v and npm -v

Project Setup (Local)
Clone the repository:

git clone https://github.com/YOUR_GITHUB_USERNAME/AndroidStaticAnalyzer.git
cd AndroidStaticAnalyzer # Navigate into the main project root

(Replace YOUR_GITHUB_USERNAME with your actual GitHub username.)

Build the Java Backend (Fat JAR):
This command compiles the Java code and packages all its dependencies into a single executable JAR file.

mvn clean install

(Ensure Maven reports BUILD SUCCESS and the maven-shade-plugin ran, creating a multi-MB JAR in the target/ directory.)

Install React Frontend Dependencies:
Navigate into the frontend subdirectory and install its Node.js dependencies.

cd android-analyzer-frontend/
npm install

How to Run the Web Application (Local)
You need to run both the Java backend server and the React frontend development server simultaneously in separate terminal windows.

Terminal 1: Start the Java Backend Server

# Navigate to the backend project root
cd ~/AndroidStaticAnalyzer/

# Run the Java backend server
java -jar target/android-analyzer-1.0-SNAPSHOT.jar

Keep this terminal window open and running. It will show "SparkJava server started on port 4567. Waiting for APK uploads..."

Terminal 2: Start the React Frontend Development Server

# Navigate to the frontend project directory
cd ~/AndroidStaticAnalyzer/android-analyzer-frontend/

# Run the React development server
npm start

Keep this second terminal window open and running. This will automatically open your web browser to http://localhost:3000.

Access the Application:
Open your web browser and go to http://localhost:3000. You can then upload an APK and initiate the analysis. The PDF report will download directly to your browser.

Hosting on GitHub Pages (Frontend Only)
The ReactJS frontend can be hosted on GitHub Pages for public access.

Configure package.json (already done if you followed previous steps):
Ensure your android-analyzer-frontend/package.json has the homepage field and predeploy/deploy scripts:

{
  "name": "android-analyzer-frontend",
  "version": "0.1.0",
  "private": true,
  "homepage": "https://YOUR_GITHUB_USERNAME.github.io/AndroidStaticAnalyzer/android-analyzer-frontend/",
  "dependencies": { /* ... */ },
  "scripts": {
    "start": "react-scripts start",
    "build": "react-scripts build",
    "test": "react-scripts test",
    "eject": "react-scripts eject",
    "predeploy": "npm run build",
    "deploy": "gh-pages -d build"
  },
  "eslintConfig": { /* ... */ },
  "browserslist": { /* ... */ }
}

(Remember to replace YOUR_GITHUB_USERNAME with your actual GitHub username.)

Deploy Frontend to GitHub Pages:
Navigate to the frontend directory and run the deploy script:

cd ~/AndroidStaticAnalyzer/android-analyzer-frontend/
npm run deploy

Configure GitHub Repository (One-Time Setup in Browser):

Go to your AndroidStaticAnalyzer repository on GitHub.

Click on "Settings" -> "Pages".

Under "Build and deployment," set Source to "Deploy from a branch", Branch to gh-pages, and folder to / (root). Click "Save".

Your site will be available at https://YOUR_GITHUB_USERNAME.github.io/AndroidStaticAnalyzer/android-analyzer-frontend/ after a few minutes.

Important Note on Online Functionality:
GitHub Pages only hosts static files (your React frontend). Your Java backend server cannot be hosted directly on GitHub Pages. For your full web application to work online (i.e., for users to upload APKs from the GitHub Pages URL), you would need to:

Deploy your Java backend to a cloud server (e.g., Heroku, Google Cloud Run, AWS EC2, DigitalOcean, etc.).

Update the fetch URL in android-analyzer-frontend/src/App.js from http://localhost:4567/upload to the public URL of your deployed backend.

Contribution & Future Work
Feel free to contribute to this project! Ideas for future enhancements include:

More sophisticated Data Flow / Taint Analysis (e.g., using FlowDroid/Soot).

Handling code obfuscation.

Dependency vulnerability scanning.

An interactive HTML report viewer.

Improved UI/UX for the frontend.

License
This project is licensed under the MIT License - see the LICENSE file for details.