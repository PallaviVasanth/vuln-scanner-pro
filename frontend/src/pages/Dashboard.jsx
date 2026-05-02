import React, { useState, useEffect } from "react";
import ScanForm from "../components/ScanForm";
import ScanStatus from "../components/ScanStatus";
import VulnerabilityTable from "../components/VulnerabilityTable";
import ReportDownload from "../components/ReportDownload";
import { getResults } from "../services/api";

const Dashboard = () => {
  const [scanId, setScanId] = useState(null);
  const [results, setResults] = useState(null);

  useEffect(() => {
    if (!scanId) return;

    const fetchResults = async () => {
      const res = await getResults(scanId);
      setResults(res.data.vulnerabilities);
    };

    const interval = setInterval(fetchResults, 3000);

    return () => clearInterval(interval);
  }, [scanId]);

  return (
    <div>
      <h1>Vulnerability Scanner</h1>

      <ScanForm setScanId={setScanId} />
      <ScanStatus scanId={scanId} />

      <VulnerabilityTable data={results} />

      {scanId && <ReportDownload scanId={scanId} />}
    </div>
  );
};

export default Dashboard;