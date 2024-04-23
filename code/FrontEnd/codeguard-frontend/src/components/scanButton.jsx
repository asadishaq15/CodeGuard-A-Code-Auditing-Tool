import React from 'react';

const ScanButton = ({ onClick }) => {
    return (
        <div>
            <button onClick={onClick}>Scan</button>
        </div>
    );
}

export default ScanButton;
