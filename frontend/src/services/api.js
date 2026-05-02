import axios from "axios";

const API = axios.create({
  baseURL: "http://localhost:8000",
});

// Start scan
export const startScan = (data) =>
  API.post("/scan/start", data);  // ✅ KEEP THIS

// Status
export const getStatus = (scanId) =>
  API.get(`/scan/status/${scanId}`); // ✅ FIXED

// Results
export const getResults = (scanId) =>
  API.get(`/scan/result/${scanId}`); // ✅ FIXED

// Get report
export const getReport = (scanId) =>
  API.get(`/report/${scanId}`);