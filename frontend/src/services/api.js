import axios from "axios";

const API = axios.create({
  baseURL: "http://localhost:8000/api/v1",
});

// Start scan
export const startScan = (data) => API.post("/scan/start", data);

// Get scan status
export const getStatus = (scanId) =>
  API.get(`/scan/${scanId}/status`);

// Get results
export const getResults = (scanId) =>
  API.get(`/scan/${scanId}/results`);

// Get report
export const getReport = (scanId) =>
  API.get(`/report/${scanId}`);