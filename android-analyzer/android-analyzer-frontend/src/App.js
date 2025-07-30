import React, { useState } from 'react';

function App() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  // Handle file selection
  const handleFileChange = (event) => {
    const file = event.target.files[0];
    if (file && file.name.endsWith('.apk')) {
      setSelectedFile(file);
      setMessage(`Selected file: ${file.name}`);
      setError('');
    } else {
      setSelectedFile(null);
      setMessage('');
      setError('Please select a valid .apk file.');
    }
  };

  // Handle file upload
  const handleUpload = async () => {
    if (!selectedFile) {
      setError('Please select an APK file first.');
      return;
    }

    setUploading(true);
    setMessage('Uploading and analyzing APK...');
    setError('');

    const formData = new FormData();
    formData.append('apkFile', selectedFile); // 'apkFile' must match the backend's expected part name

    try {
      const response = await fetch('http://localhost:4567/upload', { // Backend URL
        method: 'POST',
        body: formData,
      });

      if (response.ok) {
        // If response is OK, it means a PDF is being returned
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `analysis_report_${Date.now()}.pdf`; // Suggest a filename
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url); // Clean up the URL object

        setMessage('Analysis complete! PDF report downloaded.');
        setSelectedFile(null); // Clear selected file after successful upload
      } else {
        const errorText = await response.text();
        setError(`Analysis failed: ${response.status} - ${errorText}`);
        setMessage('');
      }
    } catch (err) {
      console.error('Network or server error:', err);
      setError(`Network or server error: ${err.message}. Ensure backend is running.`);
      setMessage('');
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-100 flex items-center justify-center p-4 font-inter">
      <div className="bg-white p-8 rounded-lg shadow-xl w-full max-w-md">
        <h1 className="text-3xl font-bold text-center text-gray-800 mb-6">
          Android Static Analyzer
        </h1>

        <div className="mb-6">
          <label
            htmlFor="apk-upload"
            className="block text-sm font-medium text-gray-700 mb-2"
          >
            Upload APK File:
          </label>
          <input
            type="file"
            id="apk-upload"
            accept=".apk"
            onChange={handleFileChange}
            className="block w-full text-sm text-gray-900
                       file:mr-4 file:py-2 file:px-4
                       file:rounded-full file:border-0
                       file:text-sm file:font-semibold
                       file:bg-blue-50 file:text-blue-700
                       hover:file:bg-blue-100 cursor-pointer"
          />
        </div>

        {selectedFile && (
          <p className="text-gray-600 text-sm mb-4">
            Selected: <span className="font-semibold">{selectedFile.name}</span>
          </p>
        )}

        <button
          onClick={handleUpload}
          disabled={!selectedFile || uploading}
          className={`w-full py-3 px-4 rounded-lg font-semibold text-white
                      ${selectedFile && !uploading
                        ? 'bg-blue-600 hover:bg-blue-700'
                        : 'bg-blue-400 cursor-not-allowed'}
                      transition duration-200 ease-in-out`}
        >
          {uploading ? 'Analyzing...' : 'Analyze APK'}
        </button>

        {message && (
          <p className="mt-4 text-green-600 text-center text-sm">{message}</p>
        )}
        {error && (
          <p className="mt-4 text-red-600 text-center text-sm">{error}</p>
        )}
      </div>
    </div>
  );
}

export default App;
