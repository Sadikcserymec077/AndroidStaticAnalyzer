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

public class AnalyzerService {

    private String apkToolOutputDirName = "";
    private String jadxOutputDirName = "";
    private List<Vulnerability> vulnerabilities = new ArrayList<>();

    public AnalyzerService() {
        // Constructor, can be used for initialization if needed
    }

    /**
     * Analyzes the given APK file and generates reports.
     * @param apkFile The APK file to analyze.
     * @return Path to the generated PDF report.
     * @throws Exception if an error occurs during analysis.
     */
    public Path analyzeApk(File apkFile) throws Exception {
        vulnerabilities.clear(); // Clear previous results for a new analysis

        if (!apkFile.exists() || !apkFile.isFile()) {
            throw new IllegalArgumentException("APK file not found: " + apkFile.getAbsolutePath());
        }

        System.out.println("Starting analysis for APK: " + apkFile.getName());

        // Define temporary directories for decompiled output
        apkToolOutputDirName = "apktool_output_" + System.currentTimeMillis();
        File apkToolOutputDir = new File(apkToolOutputDirName);

        jadxOutputDirName = "jadx_output_" + System.currentTimeMillis();
        File jadxOutputDir = new File(jadxOutputDirName);

        Path pdfReportPath = null;

        try {
            // --- Phase 1: APKTool Decompilation (for AndroidManifest.xml) ---
            System.out.println("Phase 1: APKTool Manifest Extraction...");
            executeCommand("apktool", "d", apkFile.getAbsolutePath(), "-o", apkToolOutputDir.getAbsolutePath());
            System.out.println("APK decompiled by APKTool to: " + apkToolOutputDir.getAbsolutePath());

            // --- Phase 2: Manifest Analysis Checks ---
            System.out.println("Phase 2: AndroidManifest.xml Analysis...");
            performManifestAnalysis(apkToolOutputDir);

            // --- Phase 3: JADX Decompilation (for Java Source Code) ---
            System.out.println("Phase 3: JADX Code Decompilation...");
            executeCommand("jadx", "-d", jadxOutputDir.getAbsolutePath(), apkFile.getAbsolutePath());
            System.out.println("APK decompiled by JADX to: " + jadxOutputDir.getAbsolutePath());

            // --- Phase 4: Code Analysis (Hardcoded Strings & Insecure API Usage) ---
            System.out.println("Phase 4: Code Analysis...");
            performCodeAnalysis(jadxOutputDir);

            // --- Final Step: Generate Reports ---
            System.out.println("Generating Reports...");
            // JSON Report (optional, but good for debugging/API response)
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            String jsonReport = gson.toJson(vulnerabilities);
            String jsonReportFileName = "analysis_report_" + System.currentTimeMillis() + ".json";
            Path jsonReportFilePath = Paths.get("target", jsonReportFileName); // Save to target/
            Files.writeString(jsonReportFilePath, jsonReport);
            System.out.println("JSON report saved to: " + jsonReportFilePath.toAbsolutePath());

            // PDF Report (main output for web)
            String pdfReportFileName = "analysis_report_" + System.currentTimeMillis() + ".pdf";
            pdfReportPath = Paths.get("target", pdfReportFileName); // Save to target/
            generatePdfReport(vulnerabilities, pdfReportPath.toString());
            System.out.println("PDF report saved to: " + pdfReportPath.toAbsolutePath());

        } finally {
            // --- Phase 5: Cleanup ---
            System.out.println("Cleaning up temporary directories...");
            deleteTemporaryDirectory(apkToolOutputDir);
            deleteTemporaryDirectory(jadxOutputDir);
            System.out.println("Analysis complete.");
        }
        return pdfReportPath; // Return the path to the generated PDF
    }

    // Helper method to execute external commands (apktool, jadx)
    private void executeCommand(String... command) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true); // Merge error stream with input stream

        Process process = pb.start();
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            // For web service, we might not want to print all tool output to console
            // but rather log it or suppress it unless there's an error.
            // For now, we'll print it to still see progress.
            System.out.println("Tool Output: " + line);
        }
        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new RuntimeException("Command failed with exit code " + exitCode + ": " + String.join(" ", command));
        }
    }

    // Method to perform analysis on AndroidManifest.xml
    private void performManifestAnalysis(File apkToolOutputDir) throws Exception {
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
            if (!"false".equalsIgnoreCase(allowBackupAttribute)) {
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
    private void performCodeAnalysis(File jadxOutputDir) {
        Path javaSourceRoot = Paths.get(jadxOutputDir.getAbsolutePath(), "sources");

        if (!Files.exists(javaSourceRoot)) {
            System.err.println("Warning: JADX 'sources' directory not found at " + javaSourceRoot + ". Skipping code analysis.");
            return;
        }

        try (Stream<Path> paths = Files.walk(javaSourceRoot)) {
            paths.filter(Files::isRegularFile)
                 .filter(path -> path.toString().endsWith(".java"))
                 .forEach(javaFilePath -> {
                     scanJavaFileForHardcodedStrings(javaFilePath);
                     scanJavaFileForInsecureApiUsage(javaFilePath);
                 });
        } catch (Exception e) {
            System.err.println("Error walking Java source directory: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // Method to scan individual Java files for hardcoded strings
    private void scanJavaFileForHardcodedStrings(Path javaFilePath) {
        try {
            List<String> lines = Files.readAllLines(javaFilePath);
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

                    String lowerCaseMatch = matchedString.toLowerCase();
                    if (
                        lowerCaseMatch.length() < 8 ||
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

                    String relativePath = javaFilePath.toString().replace(jadxOutputDirName + File.separator, "");
                    vulnerabilities.add(new Vulnerability(type, description, severity, relativePath, details));
                }
            }
        } catch (Exception e) {
            System.err.println("Error scanning file " + javaFilePath + " for hardcoded strings: " + e.getMessage());
        }
    }

    // Method: Scans individual Java files for insecure API usage
    private void scanJavaFileForInsecureApiUsage(Path javaFilePath) {
        try {
            List<String> lines = Files.readAllLines(javaFilePath);
            String relativePath = javaFilePath.toString().replace(jadxOutputDirName + File.separator, "");

            Pattern webviewJsEnabledPattern = Pattern.compile(
                "\\.setJavaScriptEnabled\\(\\s*true\\s*\\)",
                Pattern.CASE_INSENSITIVE
            );

            Pattern sensitiveLogPattern = Pattern.compile(
                "android\\.util\\.Log\\.(d|i|w|e|v|wtf)\\(.*?(\"password\"|\"secret\"|\"token\"|\"key\"|pass|secret|token|key|pwd).*?\\)",
                Pattern.CASE_INSENSITIVE | Pattern.DOTALL
            );

            Pattern sensitiveInputToLogPattern = Pattern.compile(
                "(String\\s+\\w+\\s*=\\s*(?:intent\\.getStringExtra|editText\\.getText)\\([^)]*\\);\\s*|)" +
                "android\\.util\\.Log\\.(d|i|w|e|v|wtf)\\(.*?(\\b\\w+\\b|\\\"password\\\"|\\\"secret\\\").*?\\)",
                Pattern.CASE_INSENSITIVE | Pattern.DOTALL
            );

            Pattern weakCipherPattern = Pattern.compile(
                "Cipher\\.getInstance\\([\"'](AES\\/ECB|DES|RC4|PBEWithMD5AndDES).*?[\"']\\)",
                Pattern.CASE_INSENSITIVE
            );

            Pattern insecureFileModePattern = Pattern.compile(
                "Context\\s*\\.\\s*(?:MODE_WORLD_READABLE|MODE_WORLD_WRITABLE)",
                Pattern.CASE_INSENSITIVE
            );

            // NEW Pattern 3: Insecure TLS/SSL Certificate Validation
            Pattern insecureCertValidationPattern = Pattern.compile(
                "(HttpsURLConnection\\.setDefaultHostnameVerifier\\(SSLCertificateSocketFactory\\.ALLOW_ALL_HOSTNAME_VERIFIER\\)|" +
                "new\\s+X509TrustManager\\(\\s*\\)\\s*\\{.*?checkClientTrusted.*?checkServerTrusted.*?getAcceptedIssuers.*?\\}\\)|" +
                "new\\s+HostnameVerifier\\(\\s*\\)\\s*\\{.*?verify\\(.*?true\\).*?\\})",
                Pattern.CASE_INSENSITIVE | Pattern.DOTALL
            );

            // NEW Pattern 4: Hardcoded Cryptographic Keys or IVs
            Pattern hardcodedCryptoPattern = Pattern.compile(
                "(byte\\[\\]\\s+\\w+\\s*=\\s*new\\s+byte\\[\\]\\s*\\{[^}]+}|String\\s+\\w+\\s*=\\s*\"[a-fA-F0-9]{16,}\"\\s*\\.\\s*(?:getBytes|decode)|" +
                "(?:SecretKeySpec|IvParameterSpec)\\s*\\([^,]+\\s*,\\s*\"[A-Z]+\"\\s*\\)|" +
                "(key|iv|salt|password)\\s*=\\s*\"([a-zA-Z0-9!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?`~]{16,})\""
                , Pattern.CASE_INSENSITIVE
            );


            for (int i = 0; i < lines.size(); i++) {
                String line = lines.get(i);
                String lowerCaseLine = line.toLowerCase();

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

                Matcher inputToLogMatcher = sensitiveInputToLogPattern.matcher(line);
                if (inputToLogMatcher.find()) {
                    String matchedSnippet = inputToLogMatcher.group(0);
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
            }
        } catch (Exception e) {
            System.err.println("Error scanning file " + javaFilePath + " for insecure API usage: " + e.getMessage());
        }
    }


    private void deleteTemporaryDirectory(File directory) {
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

    private void generatePdfReport(List<Vulnerability> vulnerabilities, String fileName) throws Exception {
        PDDocument document = new PDDocument();
        PDPage page = new PDPage(PDRectangle.A4);
        document.addPage(page);

        PDPageContentStream contentStream = new PDPageContentStream(document, page);

        float startX = 50;
        float startY = page.getMediaBox().getHeight() - 50;
        float currentY = startY;
        float lineSpacing = 15;
        float headerSpacing = 30;
        float vulnerabilitySpacing = 40;

        contentStream.setFont(PDType1Font.HELVETICA_BOLD, 18);
        contentStream.beginText();
        contentStream.newLineAtOffset(startX, currentY);
        contentStream.showText("Android Static Analysis Report");
        contentStream.endText();

        currentY -= headerSpacing;

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
                if (currentY < 100) {
                    contentStream.close();
                    page = new PDPage(PDRectangle.A4);
                    document.addPage(page);
                    contentStream = new PDPageContentStream(document, page);
                    currentY = page.getMediaBox().getHeight() - 50;
                    contentStream.setFont(PDType1Font.HELVETICA_BOLD, 14);
                    contentStream.beginText();
                    contentStream.newLineAtOffset(startX, currentY);
                    contentStream.showText("Detected Vulnerabilities (continued):");
                    contentStream.endText();
                    currentY -= lineSpacing;
                }

                contentStream.setFont(PDType1Font.HELVETICA_BOLD, 12);
                contentStream.beginText();
                currentY -= vulnerabilitySpacing;
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

                contentStream.setFont(PDType1Font.HELVETICA, 9);
                currentY -= lineSpacing;
                List<String> detailsLines = splitTextIntoLines(vul.getDetails(), 500, PDType1Font.HELVETICA, 9);
                for (String detailLine : detailsLines) {
                    if (currentY < 50) {
                        contentStream.close();
                        page = new PDPage(PDRectangle.A4);
                        document.addPage(page);
                        contentStream = new PDPageContentStream(document, page);
                        currentY = page.getMediaBox().getHeight() - 50;
                        contentStream.setFont(PDType1Font.HELVETICA, 9);
                    }
                    contentStream.beginText();
                    contentStream.newLineAtOffset(startX + 10, currentY);
                    contentStream.showText("  " + detailLine);
                    contentStream.endText();
                    currentY -= (lineSpacing - 2);
                }
                currentY -= (lineSpacing * 0.5);
            }
        }

        contentStream.close();
        document.save(fileName);
        document.close();
    }

    private List<String> splitTextIntoLines(String text, float maxWidth, PDType1Font font, float fontSize) throws Exception {
        List<String> lines = new ArrayList<>();
        String[] words = text.split(" ");
        StringBuilder currentLine = new StringBuilder();

        for (String word : words) {
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
        lines.add(currentLine.toString());
        return lines;
    }
}
