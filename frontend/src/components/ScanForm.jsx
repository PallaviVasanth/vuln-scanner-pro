import React, { useState } from "react";
import { startScan } from "../services/api";

const ScanForm = ({ setScanId }) => {
  const [target, setTarget] = useState("");

  const handleSubmit = async () => {
    try {
      const res = await startScan({
        target,
        scan_type: "full",
      });

      setScanId(res.data.scan_id);
    } catch (err) {
      console.error(err);
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
      <button onClick={handleSubmit}>Scan</button>
    </div>
  );
};

export default ScanForm;