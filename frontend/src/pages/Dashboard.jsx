import React, { useState, useEffect, useRef } from "react";
import ScanForm from "../components/ScanForm";
import ScanStatus from "../components/ScanStatus";
import VulnerabilityTable from "../components/VulnerabilityTable";
import ReportDownload from "../components/ReportDownload";
import { getResults } from "../services/api";

const Dashboard = () => {
  const [scanId, setScanId] = useState(null);
  const [results, setResults] = useState(null);
  const intervalRef = useRef(null);   // ← stable ref, no closure issue

  useEffect(() => {
    if (!scanId) return;

    const fetchResults = async () => {
      try {
        const res = await getResults(scanId);
        setResults(res.data.vulnerabilities);

        if (res.data.status === "completed" || res.data.status === "failed") {
          clearInterval(intervalRef.current);  // ← always defined
          intervalRef.current = null;
        }
      } catch (err) {
        console.error("Polling error:", err);
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
    };

    intervalRef.current = setInterval(fetchResults, 3000);

    return () => {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    };
  }, [scanId]);

  return (
    <div className="container">
      <h1 style={{ marginBottom: "20px" }}>
        🔐 Vulnerability Scanner Dashboard
      </h1>
      <div className="card"><ScanForm setScanId={setScanId} /></div>
      <div className="card"><ScanStatus scanId={scanId} /></div>
      <div className="card"><VulnerabilityTable data={results} /></div>
      {scanId && (
        <div className="card"><ReportDownload scanId={scanId} /></div>
      )}
    </div>
  );
};

export default Dashboard;