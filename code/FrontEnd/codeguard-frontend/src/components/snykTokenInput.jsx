import React, { useState } from 'react';

const SnykTokenInput = ({ onSubmit }) => {
    const [token, setToken] = useState('');

    const handleChange = (event) => {
        setToken(event.target.value);
    };

    const handleSubmit = () => {
        onSubmit(token);
    };

    return (
        <div>
            <h3>Enter Snyk Token</h3>
            <input
                type="text"
                value={token}
                onChange={handleChange}
                placeholder="Enter your Snyk token"
            />
            <button onClick={handleSubmit}>Submit</button>
        </div>
    );
}

export default SnykTokenInput;
