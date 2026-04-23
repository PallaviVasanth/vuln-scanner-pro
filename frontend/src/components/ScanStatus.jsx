import React, { useEffect, useState } from "react";
import { getStatus } from "../services/api";

const ScanStatus = ({ scanId }) => {
  const [status, setStatus] = useState(null);

  useEffect(() => {
    if (!scanId) return;

    const interval = setInterval(async () => {
      const res = await getStatus(scanId);
      setStatus(res.data);

      if (res.data.status === "completed") {
        clearInterval(interval);
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [scanId]);

  if (!status) return null;

  return (
    <div>
      <h3>Status: {status.status}</h3>
      <p>Progress: {status.progress}%</p>
      <p>Stage: {status.current_stage}</p>
    </div>
  );
};

export default ScanStatus;