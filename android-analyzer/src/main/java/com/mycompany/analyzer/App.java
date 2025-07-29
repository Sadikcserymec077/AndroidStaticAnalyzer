package com.mycompany.analyzer;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.common.PDRectangle;

public class App {

    // List to store all detected vulnerabilities
    private static List<Vulnerability> vulnerabilities = new ArrayList<>();
    // To keep track of temporary output directories for cleanup
    private static String apkToolOutputDirName = "";
    private static String jadxOutputDirName = "";

    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Usage: java -jar android-analyzer-1.0-SNAPSHOT.jar <path_to_apk>");
            return;
        }

        String apkPath = args[0];
        File apkFile = new File(apkPath);

        if (!apkFile.exists() || !apkFile.isFile()) {
            System.out.println("Error: APK file not found at " + apkPath);
            return;
        }

        System.out.println("Analyzing APK: " + apkPath);

        // Define temporary directories for decompiled output
        apkToolOutputDirName = "apktool_output_" + System.currentTimeMillis();
        File apkToolOutputDir = new File(apkToolOutputDirName);

        jadxOutputDirName = "jadx_output_" + System.currentTimeMillis();
        File jadxOutputDir = new File(jadxOutputDirName);


        try {
            // --- Phase 1: APKTool Decompilation (for AndroidManifest.xml) ---
            System.out.println("\n--- Phase 1: APKTool Manifest Extraction ---");
            // Command: apktool d <apk_path> -o <output_dir>
            ProcessBuilder pbApkTool = new ProcessBuilder("apktool", "d", apkPath, "-o", apkToolOutputDir.getAbsolutePath());
            pbApkTool.redirectErrorStream(true); // Merge error stream with input stream

            Process processApkTool = pbApkTool.start();

            BufferedReader readerApkTool = new BufferedReader(new InputStreamReader(processApkTool.getInputStream()));
            String line;
            while ((line = readerApkTool.readLine()) != null) {
                System.out.println("APKTool: " + line); // Print apktool's output
            }

            int exitCodeApkTool = processApkTool.waitFor(); // Wait for apktool to finish
            if (exitCodeApkTool != 0) {
                System.err.println("Error: apktool command failed with exit code " + exitCodeApkTool);
                return; // Exit if apktool fails
            }
            System.out.println("APK decompiled by APKTool to: " + apkToolOutputDir.getAbsolutePath());

            // --- Phase 2: Manifest Analysis Checks ---
            System.out.println("\n--- Phase 2: AndroidManifest.xml Analysis ---");
            performManifestAnalysis(apkToolOutputDir);

            // --- Phase 3: JADX Decompilation (for Java Source Code) ---
            System.out.println("\n--- Phase 3: JADX Code Decompilation ---");
            // Command: jadx -d <output_dir> <apk_path>
            ProcessBuilder pbJadx = new ProcessBuilder("jadx", "-d", jadxOutputDir.getAbsolutePath(), apkPath);
            pbJadx.redirectErrorStream(true);

            Process processJadx = pbJadx.start();
            BufferedReader readerJadx = new BufferedReader(new InputStreamReader(processJadx.getInputStream()));
            while ((line = readerJadx.readLine()) != null) {
                // Suppress some verbose JADX output, show errors/warnings
                if (line.contains("ERROR") || line.contains("WARN")) {
                    System.err.println("JADX: " + line);
                } else if (line.contains("loading")) { // Show loading progress
                     System.out.println("JADX: " + line);
                }
            }
            int exitCodeJadx = processJadx.waitFor();
            if (exitCodeJadx != 0) {
                System.err.println("Error: JADX command failed with exit code " + exitCodeJadx + ". Code analysis might be incomplete.");
                // We don't return here, as we might still have manifest results
            }
            System.out.println("APK decompiled by JADX to: " + jadxOutputDir.getAbsolutePath());

            // --- Phase 4: Code Analysis (Hardcoded Strings & Insecure API Usage) ---
            System.out.println("\n--- Phase 4: Code Analysis ---");
            performCodeAnalysis(jadxOutputDir);


        } catch (Exception e) {
            System.err.println("An error occurred during analysis: " + e.getMessage());
            e.printStackTrace();
        } finally {
            // --- Phase 5: Cleanup ---
            System.out.println("\n--- Cleaning up temporary directories ---");
            deleteTemporaryDirectory(apkToolOutputDir);
            deleteTemporaryDirectory(jadxOutputDir);
        }

        // --- Final Step: Report All Detected Vulnerabilities (Console, JSON, & PDF File) ---
        System.out.println("\n--- Analysis Summary (Console Output) ---");
        if (vulnerabilities.isEmpty()) {
            System.out.println("No immediate vulnerabilities found based on current checks. Good job!");
        } else {
            System.out.println("Detected " + vulnerabilities.size() + " potential vulnerabilities:");
            for (Vulnerability vul : vulnerabilities) {
                System.out.println("------------------------------------------");
                System.out.println(vul.toString());
            }
            System.out.println("------------------------------------------");
        }

        // Generate and save JSON report
        System.out.println("\n--- Generating JSON Report ---");
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String jsonReport = gson.toJson(vulnerabilities);
        String jsonReportFileName = "analysis_report_" + System.currentTimeMillis() + ".json";
        Path jsonReportFilePath = Paths.get("target", jsonReportFileName); // NEW: Saves to target/
        try {
            Files.writeString(jsonReportFilePath, jsonReport);
            System.out.println("JSON report saved to: " + jsonReportFilePath.toAbsolutePath());
        } catch (Exception e) {
            System.err.println("Error saving JSON report: " + e.getMessage());
            e.printStackTrace();
        }

        // Generate and save PDF report
        String pdfReportFileName = "analysis_report_" + System.currentTimeMillis() + ".pdf";
        Path pdfReportFilePath = Paths.get("target", pdfReportFileName); // NEW: Saves to target/
        try {
            generatePdfReport(vulnerabilities, pdfReportFileName);
            System.out.println("PDF report saved to: " + Paths.get(pdfReportFileName).toAbsolutePath());
        } catch (Exception e) {
            System.err.println("Error generating PDF report: " + e.getMessage());
            e.printStackTrace();
        }

    } // End of main method

    // --- Helper Methods ---

    // Method to perform analysis on AndroidManifest.xml
    private static void performManifestAnalysis(File apkToolOutputDir) throws Exception {
        File manifestFile = new File(apkToolOutputDir, "AndroidManifest.xml");
        if (!manifestFile.exists()) {
            System.err.println("Warning: AndroidManifest.xml not found for analysis.");
            return;
        }

        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        Document doc = dBuilder.parse(manifestFile);
        doc.getDocumentElement().normalize();

        Element applicationElement = (Element) doc.getElementsByTagName("application").item(0);

        // Check 1: android:debuggable="true"
        if (applicationElement != null) {
            String debuggableAttribute = applicationElement.getAttribute("android:debuggable");
            if ("true".equalsIgnoreCase(debuggableAttribute)) {
                vulnerabilities.add(new Vulnerability(
                    "Insecure Debuggable Flag",
                    "The 'android:debuggable' flag is set to 'true' in AndroidManifest.xml.",
                    "High",
                    "AndroidManifest.xml",
                    "This allows attackers to debug your application, potentially gaining access to sensitive data or bypassing security controls. Ensure this is 'false' in production builds."
                ));
            }
        }

        // Check 2: android:allowBackup="true"
        if (applicationElement != null) {
            String allowBackupAttribute = applicationElement.getAttribute("android:allowBackup");
            // By default, allowBackup is true if not explicitly set to false for targetSdkVersion < 31
            // For simplicity, we flag if explicitly true or not explicitly false
            if (!"false".equalsIgnoreCase(allowBackupAttribute)) { // Only flag if not explicitly set to false
                vulnerabilities.add(new Vulnerability(
                    "Insecure Backup Allowed",
                    "The 'android:allowBackup' flag is not explicitly set to 'false' (or is set to 'true').",
                    "Medium",
                    "AndroidManifest.xml",
                    "This allows users (or attackers with adb access) to backup and restore application data, including sensitive information. Set 'android:allowBackup=\"false\"' to prevent this, or implement a custom backup agent to secure sensitive data."
                ));
            }
        }

        // Check 3: Exported Components Without Permission (Activities, Services, Receivers, Providers)
        String[] componentTypes = {"activity", "service", "receiver", "provider"};
        for (String componentType : componentTypes) {
            NodeList components = doc.getElementsByTagName(componentType);
            for (int i = 0; i < components.getLength(); i++) {
                Element componentElement = (Element) components.item(i);
                String exportedAttribute = componentElement.getAttribute("android:exported");
                String permissionAttribute = componentElement.getAttribute("android:permission");

                boolean isExplicitlyExported = "true".equalsIgnoreCase(exportedAttribute);
                boolean hasIntentFilter = componentElement.getElementsByTagName("intent-filter").getLength() > 0;
                // For targetSdkVersion < 31, if a component has an intent-filter and no explicit exported attribute, it's implicitly exported.
                // For API 31+, components with intent filters are NOT exported by default unless explicitly set to true.
                // This check is a basic one and might need refinement for specific API levels.
                boolean isImplicitlyExported = !isExplicitlyExported && hasIntentFilter;

                if ((isExplicitlyExported || isImplicitlyExported) && (permissionAttribute == null || permissionAttribute.isEmpty())) {
                    String componentName = componentElement.getAttribute("android:name");
                    vulnerabilities.add(new Vulnerability(
                        "Unprotected Exported Component",
                        "An exported " + componentType + " ('" + componentName + "') does not require a permission.",
                        "High",
                        "AndroidManifest.xml",
                        "Exported components without proper permission protection can be invoked by any other application, potentially leading to unauthorized access, data leakage, or denial of service. Apply appropriate 'android:permission' to restrict access."
                    ));
                }
            }
        }

        // Check 4: usesCleartextTraffic
        // This flag, if true, explicitly allows unencrypted HTTP traffic. Default is false from API 28.
        if (applicationElement != null) {
            String cleartextTrafficAttribute = applicationElement.getAttribute("android:usesCleartextTraffic");
            if ("true".equalsIgnoreCase(cleartextTrafficAttribute)) {
                 vulnerabilities.add(new Vulnerability(
                    "Cleartext Traffic Allowed",
                    "The 'android:usesCleartextTraffic' flag is explicitly set to 'true'.",
                    "Medium",
                    "AndroidManifest.xml",
                    "This flag allows the application to use unencrypted HTTP connections. Sensitive data transmitted over unencrypted channels can be intercepted. Always use HTTPS for network communication."
                ));
            }
        }
    }

    // Method to perform general code analysis, including hardcoded strings and insecure API usage
    private static void performCodeAnalysis(File jadxOutputDir) {
        // JADX extracts sources into a 'sources' folder within its output directory
        Path javaSourceRoot = Paths.get(jadxOutputDir.getAbsolutePath(), "sources");

        if (!Files.exists(javaSourceRoot)) {
            System.err.println("Warning: JADX 'sources' directory not found at " + javaSourceRoot + ". Skipping code analysis.");
            return;
        }

        try (Stream<Path> paths = Files.walk(javaSourceRoot)) {
            paths.filter(Files::isRegularFile)
                 .filter(path -> path.toString().endsWith(".java"))
                 .forEach(javaFilePath -> { // Use lambda to pass file path
                     scanJavaFileForHardcodedStrings(javaFilePath);
                     scanJavaFileForInsecureApiUsage(javaFilePath);
                 });
        } catch (Exception e) {
            System.err.println("Error walking Java source directory: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // Method to scan individual Java files for hardcoded strings
    private static void scanJavaFileForHardcodedStrings(Path javaFilePath) {
        try {
            List<String> lines = Files.readAllLines(javaFilePath);
            // Patterns for common hardcoded sensitive data
            Pattern sensitivePattern = Pattern.compile(
                "\"?(API_KEY|SECRET|PASSWORD|TOKEN|AUTH_KEY|ENCRYPTION_KEY|PASS|KEY|CREDENTIALS|PW)[_\\s]*?(=|:)?\\s*[\"']([a-zA-Z0-9!@#$%^&*()_+\\-\\[\\]{};':\\\\|,.<>/?`~]{8,})[\"']?|" +
                "https?://(?:www\\.)?(?:api|auth|login|oauth|secret|key|token)[a-zA-Z0-9./_\\-]+",
                Pattern.CASE_INSENSITIVE
            );

            for (int i = 0; i < lines.size(); i++) {
                String line = lines.get(i);
                Matcher matcher = sensitivePattern.matcher(line);
                while (matcher.find()) {
                    String matchedString = matcher.group(0);
                    String type = "Hardcoded Sensitive Information";
                    String description = "Potential hardcoded sensitive data found in source code.";
                    String severity = "High";
                    String details = "Found: '" + matchedString + "' in line " + (i + 1) + ". Avoid hardcoding sensitive values directly in code. Use Android Keystore, environment variables, or secure configuration files.";

                    // --- Basic False Positive Filtering ---
                    String lowerCaseMatch = matchedString.toLowerCase();
                    if (
                        lowerCaseMatch.length() < 8 || // Ignore very short matches unless highly specific
                        lowerCaseMatch.contains("schema.org") ||
                        lowerCaseMatch.contains("schemas.android.com") ||
                        lowerCaseMatch.contains("googleusercontent.com") ||
                        lowerCaseMatch.contains("firebaseio.com") ||
                        lowerCaseMatch.contains("android.intent.action") ||
                        lowerCaseMatch.contains("public static final string") ||
                        lowerCaseMatch.contains("http://localhost") ||
                        lowerCaseMatch.contains("http://127.0.0.1") ||
                        lowerCaseMatch.contains("test.example.com") ||
                        lowerCaseMatch.matches(".*(true|false|null|0|1|2|3|4|5|6|7|8|9)$")
                    ) {
                        continue;
                    }

                    // Add the vulnerability if it passes filtering
                    String relativePath = javaFilePath.toString().replace(jadxOutputDirName + File.separator, "");
                    vulnerabilities.add(new Vulnerability(type, description, severity, relativePath, details));
                }
            }
        } catch (Exception e) {
            System.err.println("Error scanning file " + javaFilePath + " for hardcoded strings: " + e.getMessage());
        }
    }

    // Method: Scans individual Java files for insecure API usage
    private static void scanJavaFileForInsecureApiUsage(Path javaFilePath) {
        try {
            List<String> lines = Files.readAllLines(javaFilePath);
            String relativePath = javaFilePath.toString().replace(jadxOutputDirName + File.separator, "");

            // Regex for WebView.setJavaScriptEnabled(true)
            Pattern webviewJsEnabledPattern = Pattern.compile(
                "\\.setJavaScriptEnabled\\(\\s*true\\s*\\)",
                Pattern.CASE_INSENSITIVE
            );

            // Regex for sensitive data logging (Log.d/i/e/w with potentially sensitive variable names)
            Pattern sensitiveLogPattern = Pattern.compile(
                "android\\.util\\.Log\\.(d|i|w|e|v|wtf)\\(.*?(\"password\"|\"secret\"|\"token\"|\"key\"|pass|secret|token|key|pwd).*?\\)",
                Pattern.CASE_INSENSITIVE | Pattern.DOTALL
            );

            // Regex for simplified sensitive input to log sink (basic flow simulation)
            Pattern sensitiveInputToLogPattern = Pattern.compile(
                "(String\\s+\\w+\\s*=\\s*(?:intent\\.getStringExtra|editText\\.getText)\\([^)]*\\);\\s*|)" +
                "android\\.util\\.Log\\.(d|i|w|e|v|wtf)\\(.*?(\\b\\w+\\b|\\\"password\\\"|\\\"secret\\\").*?\\)",
                Pattern.CASE_INSENSITIVE | Pattern.DOTALL
            );

            // NEW Pattern 1: Weak Cryptography (e.g., AES/ECB/PKCS5Padding, DES)
            Pattern weakCipherPattern = Pattern.compile(
                "Cipher\\.getInstance\\([\"'](AES\\/ECB|DES|RC4|PBEWithMD5AndDES).*?[\"']\\)",
                Pattern.CASE_INSENSITIVE
            );

            // NEW Pattern 2: Insecure File Mode (MODE_WORLD_READABLE/WRITABLE)
            Pattern insecureFileModePattern = Pattern.compile(
                "Context\\s*\\.\\s*(?:MODE_WORLD_READABLE|MODE_WORLD_WRITABLE)",
                Pattern.CASE_INSENSITIVE
            );
            // ... inside scanJavaFileForInsecureApiUsage method ...
// ... (existing patterns: webviewJsEnabledPattern, sensitiveLogPattern, sensitiveInputToLogPattern, weakCipherPattern, insecureFileModePattern) ...

// NEW Pattern 3: Insecure TLS/SSL Certificate Validation
// Looks for patterns that disable SSL certificate validation (e.g., trustAllCertificates, insecure hostname verifiers)
Pattern insecureCertValidationPattern = Pattern.compile(
    "(HttpsURLConnection\\.setDefaultHostnameVerifier\\(SSLCertificateSocketFactory\\.ALLOW_ALL_HOSTNAME_VERIFIER\\)|" +
    "new\\s+X509TrustManager\\(\\s*\\)\\s*\\{.*?checkClientTrusted.*?checkServerTrusted.*?getAcceptedIssuers.*?\\}\\)|" +
    "new\\s+HostnameVerifier\\(\\s*\\)\\s*\\{.*?verify\\(.*?true\\).*?\\})",
    Pattern.CASE_INSENSITIVE | Pattern.DOTALL // DOTALL for multiline matches within anonymous classes
);

// NEW Pattern 4: Hardcoded Cryptographic Keys or IVs
// Looks for byte arrays or strings assigned to variables named like 'key' or 'iv' or 'salt'
// and containing what looks like a hardcoded value (e.g., new byte[]{...}, "abcdef1234567890...")
Pattern hardcodedCryptoPattern = Pattern.compile(
    "(byte\\[\\]\\s+\\w+\\s*=\\s*new\\s+byte\\[\\]\\s*\\{[^}]+}|String\\s+\\w+\\s*=\\s*\"[a-fA-F0-9]{16,}\"\\s*\\.\\s*(?:getBytes|decode)|" + // Hex string or byte array
    "(?:SecretKeySpec|IvParameterSpec)\\s*\\([^,]+\\s*,\\s*\"[A-Z]+\"\\s*\\)|" + // Key/IV spec with hardcoded key/iv
    "(key|iv|salt|password)\\s*=\\s*\"([a-zA-Z0-9!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?`~]{16,})\"" // Variable assignment like key = "..."
    , Pattern.CASE_INSENSITIVE
);

for (int i = 0; i < lines.size(); i++) {
    String line = lines.get(i);
    String lowerCaseLine = line.toLowerCase();

    // ... Existing Checks (WebView, Sensitive Log, Simplified Taint Flow, Weak Cryptography, Insecure File Mode) ...

    // Check 6: Insecure Certificate Validation
    Matcher insecureCertMatcher = insecureCertValidationPattern.matcher(line);
    if (insecureCertMatcher.find()) {
        String matchedSnippet = insecureCertMatcher.group(0);
        vulnerabilities.add(new Vulnerability(
            "Insecure Certificate/Hostname Validation",
            "Weak or missing SSL/TLS certificate or hostname validation detected.",
            "High",
            relativePath,
            "Found: '" + matchedSnippet + "' in line " + (i + 1) + ". This bypasses trust checks, making the app vulnerable to Man-in-the-Middle (MITM) attacks. Always perform proper certificate and hostname verification."
        ));
    }

    // Check 7: Hardcoded Cryptographic Keys/IVs
    Matcher hardcodedCryptoMatcher = hardcodedCryptoPattern.matcher(line);
    if (hardcodedCryptoMatcher.find()) {
        String matchedSnippet = hardcodedCryptoMatcher.group(0);
        // Basic filtering to reduce false positives for very common, non-secret strings
        if (!lowerCaseLine.contains("android.security.") && !lowerCaseLine.contains("context.registerreceiver") && !lowerCaseLine.contains("new string(")) {
            vulnerabilities.add(new Vulnerability(
                "Hardcoded Cryptographic Key/IV/Salt",
                "A cryptographic key, IV (Initialization Vector), or salt is hardcoded in source code.",
                "High",
                relativePath,
                "Found: '" + matchedSnippet + "' in line " + (i + 1) + ". Hardcoding cryptographic secrets severely compromises the security of encrypted data. Use Android Keystore or a secure key management system."
            ));
        }
    }
    // ... rest of the for loop and the method ...
}

            // --- SINGLE LOOP FOR ALL CHECKS ---
            for (int i = 0; i < lines.size(); i++) {
                String line = lines.get(i);
                String lowerCaseLine = line.toLowerCase(); // Use for case-insensitive checks where relevant

                // Check 1: WebView.setJavaScriptEnabled(true)
                Matcher webviewJsMatcher = webviewJsEnabledPattern.matcher(line);
                if (webviewJsMatcher.find()) {
                    vulnerabilities.add(new Vulnerability(
                        "Insecure WebView Configuration",
                        "WebView.setJavaScriptEnabled(true) detected.",
                        "High",
                        relativePath,
                        "Found in line " + (i + 1) + ". Enabling JavaScript can lead to XSS vulnerabilities if loading untrusted content. Ensure proper JS interface security and avoid loading untrusted URLs."
                    ));
                }

                // Check 2: Sensitive Data Logging
                Matcher sensitiveLogMatcher = sensitiveLogPattern.matcher(line);
                if (sensitiveLogMatcher.find()) {
                    vulnerabilities.add(new Vulnerability(
                        "Sensitive Data Logging",
                        "Potential sensitive information being logged.",
                        "Medium",
                        relativePath,
                        "Found in line " + (i + 1) + ". Logging sensitive data like passwords or tokens can lead to information disclosure. Remove sensitive data from log statements in production builds."
                    ));
                }

                // Check 3: Sensitive Input to Log Flow (Simplified)
                Matcher inputToLogMatcher = sensitiveInputToLogPattern.matcher(line);
                if (inputToLogMatcher.find()) {
                    String matchedSnippet = inputToLogMatcher.group(0);
                    // Basic filtering for common false positives where a variable might be called 'key' but isn't sensitive.
                    if (!lowerCaseLine.contains("bundle.getkey") && !lowerCaseLine.contains("map.getkey")) {
                         vulnerabilities.add(new Vulnerability(
                            "Potential Insecure Data Flow: Sensitive Input to Log",
                            "A variable potentially sourced from sensitive input (e.g., Intent, EditText) is immediately logged.",
                            "Medium",
                            relativePath,
                            "Found: '" + matchedSnippet + "' in line " + (i + 1) + ". Logging direct user input or sensitive data can lead to information disclosure. Implement proper input validation and avoid logging sensitive user data."
                        ));
                    }
                }

                // Check 4: Weak Cryptography
                Matcher weakCipherMatcher = weakCipherPattern.matcher(line);
                if (weakCipherMatcher.find()) {
                    String matchedMethod = weakCipherMatcher.group(0);
                    vulnerabilities.add(new Vulnerability(
                        "Weak Cryptographic Algorithm/Mode",
                        "Usage of a known weak cryptographic algorithm or mode detected.",
                        "High",
                        relativePath,
                        "Found: '" + matchedMethod + "' in line " + (i + 1) + ". Algorithms like DES, RC4, and modes like AES/ECB are vulnerable to attacks. Use strong algorithms (e.g., AES/GCM) and secure modes (e.g., CBC with a unique IV, GCM)."
                    ));
                }

                // Check 5: Insecure File Mode
                Matcher insecureFileModeMatcher = insecureFileModePattern.matcher(line);
                if (insecureFileModeMatcher.find()) {
                    String matchedMode = insecureFileModeMatcher.group(0);
                    vulnerabilities.add(new Vulnerability(
                        "Insecure File Storage Mode",
                        "Usage of MODE_WORLD_READABLE or MODE_WORLD_WRITABLE detected.",
                        "High",
                        relativePath,
                        "Found: '" + matchedMode + "' in line " + (i + 1) + ". Storing data with world-readable/writable permissions allows any other application to access or modify your app's private files. Use MODE_PRIVATE for sensitive data."
                    ));
                }
            }
        } catch (Exception e) {
            System.err.println("Error scanning file " + javaFilePath + " for insecure API usage: " + e.getMessage());
        }
    }


    // Helper method to recursively delete a temporary directory
    private static void deleteTemporaryDirectory(File directory) {
        if (directory.exists()) {
            System.out.println("Attempting to delete temporary directory: " + directory.getAbsolutePath());
            try {
                Files.walk(directory.toPath())
                    .sorted(java.util.Comparator.reverseOrder())
                    .map(Path::toFile)
                    .forEach(File::delete);

                if (directory.delete()) {
                    System.out.println("Successfully deleted: " + directory.getAbsolutePath());
                } else {
                    System.err.println("Failed to delete root directory: " + directory.getAbsolutePath() + ". Manual cleanup may be required.");
                }
            } catch (Exception e) {
                System.err.println("Error deleting directory " + directory.getAbsolutePath() + ": " + e.getMessage());
                e.printStackTrace();
            }
        }
    }

    // NEW METHOD: Generates a PDF report from the list of vulnerabilities
    private static void generatePdfReport(List<Vulnerability> vulnerabilities, String fileName) throws Exception {
        PDDocument document = new PDDocument();
        PDPage page = new PDPage(PDRectangle.A4); // Use A4 size page
        document.addPage(page);

        PDPageContentStream contentStream = new PDPageContentStream(document, page);

        // Define starting position and line spacing
        float startX = 50;
        float startY = page.getMediaBox().getHeight() - 50; // Top of the page, with a margin
        float currentY = startY;
        float lineSpacing = 15; // Space between lines of text
        float headerSpacing = 30; // Space after a section header
        float vulnerabilitySpacing = 40; // Space between different vulnerabilities

        // Set font and size for headers
        contentStream.setFont(PDType1Font.HELVETICA_BOLD, 18);
        contentStream.beginText();
        contentStream.newLineAtOffset(startX, currentY);
        contentStream.showText("Android Static Analysis Report");
        contentStream.endText();

        currentY -= headerSpacing; // Move down after main header

        if (vulnerabilities.isEmpty()) {
            contentStream.setFont(PDType1Font.HELVETICA, 12);
            contentStream.beginText();
            currentY -= lineSpacing;
            contentStream.newLineAtOffset(startX, currentY);
            contentStream.showText("No vulnerabilities found.");
            contentStream.endText();
        } else {
            contentStream.setFont(PDType1Font.HELVETICA_BOLD, 14);
            contentStream.beginText();
            currentY -= headerSpacing;
            contentStream.newLineAtOffset(startX, currentY);
            contentStream.showText("Detected Vulnerabilities:");
            contentStream.endText();
            currentY -= lineSpacing;

            for (Vulnerability vul : vulnerabilities) {
                // Check if new page is needed
                if (currentY < 100) { // If less than 100 units from bottom, create new page
                    contentStream.close();
                    page = new PDPage(PDRectangle.A4);
                    document.addPage(page);
                    contentStream = new PDPageContentStream(document, page);
                    currentY = page.getMediaBox().getHeight() - 50; // Reset Y for new page
                    contentStream.setFont(PDType1Font.HELVETICA_BOLD, 14); // Re-set font for new page header
                    contentStream.beginText();
                    contentStream.newLineAtOffset(startX, currentY);
                    contentStream.showText("Detected Vulnerabilities (continued):");
                    contentStream.endText();
                    currentY -= lineSpacing; // Adjust after header
                }

                contentStream.setFont(PDType1Font.HELVETICA_BOLD, 12);
                contentStream.beginText();
                currentY -= vulnerabilitySpacing; // Space before new vulnerability
                contentStream.newLineAtOffset(startX, currentY);
                contentStream.showText("Type: " + vul.getType());
                contentStream.endText();

                contentStream.setFont(PDType1Font.HELVETICA, 10);
                contentStream.beginText();
                currentY -= lineSpacing;
                contentStream.newLineAtOffset(startX, currentY);
                contentStream.showText("Severity: " + vul.getSeverity());
                contentStream.endText();

                contentStream.beginText();
                currentY -= lineSpacing;
                contentStream.newLineAtOffset(startX, currentY);
                contentStream.showText("Description: " + vul.getDescription());
                contentStream.endText();

                contentStream.beginText();
                currentY -= lineSpacing;
                contentStream.newLineAtOffset(startX, currentY);
                contentStream.showText("File: " + vul.getFile());
                contentStream.endText();

                // Details can be long, so we'll wrap text
                contentStream.setFont(PDType1Font.HELVETICA, 9);
                currentY -= lineSpacing; // Adjust for next line
                List<String> detailsLines = splitTextIntoLines(vul.getDetails(), 500, PDType1Font.HELVETICA, 9); // Max width 500
                for (String detailLine : detailsLines) {
                    if (currentY < 50) { // If getting too low, add new page
                        contentStream.close();
                        page = new PDPage(PDRectangle.A4);
                        document.addPage(page);
                        contentStream = new PDPageContentStream(document, page);
                        currentY = page.getMediaBox().getHeight() - 50;
                        contentStream.setFont(PDType1Font.HELVETICA, 9); // Re-set font for new page
                    }
                    contentStream.beginText();
                    contentStream.newLineAtOffset(startX + 10, currentY); // Indent details slightly
                    contentStream.showText("  " + detailLine);
                    contentStream.endText();
                    currentY -= (lineSpacing - 2); // Less spacing for detail lines
                }
                currentY -= (lineSpacing * 0.5); // Add a small gap after details
            }
        }

        contentStream.close(); // Close the content stream
        document.save(fileName); // Save the document
        document.close(); // Close the document
    }

    // Helper method to split long text into lines that fit within a certain width
    private static List<String> splitTextIntoLines(String text, float maxWidth, PDType1Font font, float fontSize) throws Exception {
        List<String> lines = new ArrayList<>();
        String[] words = text.split(" ");
        StringBuilder currentLine = new StringBuilder();

        for (String word : words) {
            // Check width of current line + new word
            float width = font.getStringWidth(currentLine.toString() + (currentLine.length() == 0 ? "" : " ") + word) / 1000 * fontSize;
            if (width < maxWidth) {
                if (currentLine.length() > 0) {
                    currentLine.append(" ");
                }
                currentLine.append(word);
            } else {
                lines.add(currentLine.toString());
                currentLine = new StringBuilder(word);
            }
        }
        lines.add(currentLine.toString()); // Add the last line
        return lines;
    }
}