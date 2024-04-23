import React from 'react';

const ReportFormatSelection = ({ value, onChange }) => {
    return (
        <div>
            <label>Report Format:</label>
            <select value={value} onChange={onChange}>
                <option value="JSON">JSON</option>
                <option value="PDF">PDF</option>
            </select>
        </div>
    );
}

export default ReportFormatSelection;
