package com.mycompany.analyzer;

import static spark.Spark.*;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;

import javax.servlet.MultipartConfigElement;
import javax.servlet.http.Part;

public class App {

    public static void main(String[] args) {
        // Configure SparkJava server
        port(4567); // Run on port 4567

        // NEW: Enable CORS for frontend (important for React app running on a different port)
        // Allows requests from any origin (*), for POST method, and specific headers.
        enableCORS("*", "POST", "Content-Type,Authorization");

        System.out.println("SparkJava server started on port 4567. Waiting for APK uploads...");
        System.out.println("Access the frontend at http://localhost:3000 (once React app is running)");


        // API Endpoint for APK Upload and Analysis
        post("/upload", (request, response) -> {
            // Ensure target directory exists for reports
            Files.createDirectories(Paths.get("target"));

            // Configure multipart form data for file upload
            // "/tmp" is a common temporary directory on Linux
            request.attribute("org.eclipse.jetty.multipartConfig", new MultipartConfigElement("/tmp"));

            Path uploadedApkPath = null;
            try {
                // Get the uploaded file part from the multipart request
                // "apkFile" must match the 'name' attribute of the file input in the frontend HTML/JSX
                Part filePart = request.raw().getPart("apkFile");

                // Create a temporary file to save the uploaded APK on the server
                uploadedApkPath = Files.createTempFile("uploaded_apk_", ".apk");
                try (InputStream input = filePart.getInputStream()) {
                    // Copy the uploaded file's content to the temporary file
                    Files.copy(input, uploadedApkPath, StandardCopyOption.REPLACE_EXISTING);
                }
                System.out.println("Received APK: " + uploadedApkPath.getFileName());

                // Create an instance of our AnalyzerService, which contains the core analysis logic
                AnalyzerService analyzer = new AnalyzerService();

                // Analyze the uploaded APK and get the path to the generated PDF report
                Path pdfReportPath = analyzer.analyzeApk(uploadedApkPath.toFile());

                // Set response headers to tell the browser it's a file download
                response.header("Content-Disposition", "attachment; filename=\"" + pdfReportPath.getFileName().toString() + "\"");
                // Set the content type to PDF
                response.type("application/pdf");

                // Read the PDF file into bytes and return them as the response body
                return Files.readAllBytes(pdfReportPath);

            } catch (Exception e) {
                // Log the error on the server side
                System.err.println("Error during APK upload or analysis: " + e.getMessage());
                e.printStackTrace();
                // Set HTTP status code to 500 (Internal Server Error)
                response.status(500);
                // Return an error message to the frontend
                return "Error: " + e.getMessage();
            } finally {
                // Ensure the temporary uploaded APK file is deleted after processing
                if (uploadedApkPath != null) {
                    try {
                        Files.deleteIfExists(uploadedApkPath);
                        System.out.println("Cleaned up uploaded temp APK: " + uploadedApkPath.getFileName());
                    } catch (Exception e) {
                        System.err.println("Error cleaning up temp APK: " + e.getMessage());
                    }
                }
            }
        });
    }

    // NEW HELPER METHOD: Configures Cross-Origin Resource Sharing (CORS) for the SparkJava server
    private static void enableCORS(final String origin, final String methods, final String headers) {
        // Handles preflight OPTIONS requests from the browser
        options("/*", (request, response) -> {
            String accessControlRequestHeaders = request.headers("Access-Control-Request-Headers");
            if (accessControlRequestHeaders != null) {
                response.header("Access-Control-Allow-Headers", accessControlRequestHeaders);
            }

            String accessControlRequestMethod = request.headers("Access-Control-Request-Method");
            if (accessControlRequestMethod != null) {
                response.header("Access-Control-Allow-Methods", accessControlRequestMethod);
            }

            return "OK"; // Respond to preflight with OK
        });

        // Sets CORS headers for actual requests (GET, POST, etc.)
        before((request, response) -> {
            response.header("Access-Control-Allow-Origin", origin); // Allow requests from specified origin (e.g., "*")
            response.header("Access-Control-Request-Method", methods); // Allow specified HTTP methods (e.g., "POST")
            response.header("Access-Control-Allow-Headers", headers); // Allow specified headers (e.g., "Content-Type")
            // Note: This line sets a default content type for general API responses.
            // For the /upload endpoint, this will be overridden by application/pdf.
            response.type("application/json");
        });
    }
}
