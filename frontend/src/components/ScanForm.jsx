import React, { useState } from "react";
import { startScan } from "../services/api";

const ScanForm = ({ setScanId }) => {
  const [target, setTarget] = useState("");

  const handleSubmit = async () => {
    try {
      console.log("Starting scan...");

      const res = await startScan({
        target: target,
        scan_type: "full",
      });

      console.log("Response:", res.data);

      // IMPORTANT
      setScanId(res.data.scan_id);

    } catch (err) {
      console.error("Scan error:", err);
    }
  };

  return (
    <div>
      <h2>Start Scan</h2>

      <input
        type="text"
        placeholder="Enter URL"
        value={target}
        onChange={(e) => setTarget(e.target.value)}
      />

      <button onClick={handleSubmit}>
        Start Scan
      </button>
    </div>
  );
};

export default ScanForm;