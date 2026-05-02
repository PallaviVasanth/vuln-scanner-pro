import React from "react";

const SeverityChart = ({ data }) => {
  if (!data || data.length === 0) return null;

  const counts = {
    high: 0,
    medium: 0,
    low: 0
  };

  data.forEach(v => {
    if (v.severity) {
      counts[v.severity.toLowerCase()]++;
    }
  });

  return (
    <div>
      <h3>Severity Summary</h3>
      <p>🔴 High: {counts.high}</p>
      <p>🟠 Medium: {counts.medium}</p>
      <p>🟢 Low: {counts.low}</p>
    </div>
  );
};

export default SeverityChart;