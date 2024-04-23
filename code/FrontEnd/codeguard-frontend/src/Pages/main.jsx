import React, { useState } from 'react';
import '../App.css';
import axios from 'axios';

function App() {
  const [repoUrl, setRepoUrl] = useState('');
  const [action, setAction] = useState('');
  const [snykToken, setSnykToken] = useState('');
  const [scanningInProgress, setScanningInProgress] = useState(false);
  const [scanningLogs, setScanningLogs] = useState([]);

  const handleRepoUrlChange = (e) => {
    setRepoUrl(e.target.value);
  };

  const handleActionChange = (e) => {
    setAction(e.target.value);
  };

  const handleSnykTokenChange = (e) => {
    setSnykToken(e.target.value);
  };

  
  const handleSubmit = async () => {
    try {
      setScanningInProgress(true);
      setScanningLogs(['Scanning started...']);
  
      const formData = {
        repo_url: repoUrl,
        action,
        snykToken,
      };
  
      const response = await axios.post('http://127.0.0.1:5000/perform_actions', formData);
  
      if (response.status === 200) {
        const logs = response.data.result.split('\n');
        setScanningLogs(logs);
      } else {
        setScanningLogs((prevLogs) => [...prevLogs, 'Error scanning repository. Please try again.']);
      }
  
      setScanningInProgress(false);
    } catch (error) {
      console.error('Error scanning repository:', error);
      setScanningInProgress(false);
      setScanningLogs((prevLogs) => [...prevLogs, 'Error scanning repository. Please try again.']);
    }
  };

  const handleClearForm = () => {
    setRepoUrl('');
    setAction('');
    setSnykToken('');
    setScanningInProgress(false);
    setScanningLogs([]);
  };

  return (
    <div className="app-container">
      <header className="app-header">
        <h1>Perform Actions</h1>
      </header>
      <main>
        <div className="input-section">
          <input
            type="text"
            placeholder="Enter GitHub repository URL"
            value={repoUrl}
            onChange={handleRepoUrlChange}
            className="input-field"
          />
          <select
            value={action}
            onChange={handleActionChange}
            className="scan-option-select"
          >
            <option value="">Select Action</option>
            <option value="1">Search Package.json</option>
            <option value="2">Search Package.json with Dependency Confusion Check</option>
            <option value="3">Perform Code Scanning</option>
            <option value="4">Perform Dependency Scanning</option>
            <option value="5">Check All Buckets</option>
            <option value="6">Perform All Actions</option>
          </select>
          {action === '3' || action === '4' ? ( // Render Snyk Token input if action is code scanning or dependency scanning
            <input
              type="text"
              placeholder="Snyk Token"
              value={snykToken}
              onChange={handleSnykTokenChange}
              className="input-field"
            />
          ) : null}
        </div>
        <div className="scanning-section">
        <div className="log-window">
        {[...scanningLogs.map(log => log.split('\n'))].flat().map((log, index) => (
            <div key={index} className="log-message">{log}</div>
          ))}
        </div>
          <button onClick={handleSubmit} className="submit-button" disabled={scanningInProgress}>
            {scanningInProgress ? 'Scanning...' : 'Submit'}
          </button>
          <button onClick={handleClearForm} className="clear-button">
            Clear
          </button>
        </div>
      </main>
    </div>
  );
}

export default App;
