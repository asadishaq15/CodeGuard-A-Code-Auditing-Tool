import React from 'react';

const ScanningProgress = ({ progress, messages }) => {
    return (
        <div>
            <h3>Scanning Progress</h3>
            <progress value={progress} max="100"></progress>
            <textarea value={messages} readOnly></textarea>
        </div>
    );
}

export default ScanningProgress;
