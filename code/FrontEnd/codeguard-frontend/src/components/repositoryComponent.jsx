import React from 'react';

const RepositoryInput = ({ value, onChange }) => {
    return (
        <div>
            <label htmlFor="repository-url">GitHub Repository URL:</label>
            <input
                type="text"
                id="repository-url"
                value={value}
                onChange={onChange}
            />
        </div>
    );
}

export default RepositoryInput;
