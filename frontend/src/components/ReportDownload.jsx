const ReportDownload = ({ scanId }) => {
  const handleDownload = () => {
    if (!scanId) {
      alert("No scan ID available");
      return;
    }

    window.open(`http://localhost:8000/report/download/${scanId}`, "_blank");
  };

  return (
    <button onClick={handleDownload}>
      Download Report
    </button>
  );
};

export default ReportDownload;