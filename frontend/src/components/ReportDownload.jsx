import React from "react";
import { getReport } from "../services/api";

const ReportDownload = ({ scanId }) => {
  const handleDownload = async () => {
    const res = await getReport(scanId);
    window.open(res.data.report_url, "_blank");
  };

  return <button onClick={handleDownload}>Download Report</button>;
};

export default ReportDownload;