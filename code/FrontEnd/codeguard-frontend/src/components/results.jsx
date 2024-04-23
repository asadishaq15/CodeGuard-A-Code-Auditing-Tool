import React from 'react';

const Results = ({ repositoryStatus, authenticationStatus, onSelectOption }) => {
    return (
        <div>
            <h3>Results</h3>
            <p>Repository Status: {repositoryStatus}</p>
            <p>Authentication Status: {authenticationStatus}</p>
            <h4>Select Scanning Options:</h4>
            <label>
                <input type="checkbox" value="1" onChange={() => onSelectOption(1)} />
                Check for abundant domains emails in package.json
            </label>
            {/* Add more options here */}
        </div>
    );
}

export default Results;
