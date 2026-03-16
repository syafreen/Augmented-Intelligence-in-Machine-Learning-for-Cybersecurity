import { useState, useEffect } from "react";
import * as api from "../services/api";

interface Detection {
  id: string;
  title: string;
  severity: string;
  status: string;
  time: string;
  alerts: string[];
  logs: string[];
  notes: string;
  raw?: any;
}

export default function Detection() {
  const [detections, setDetections] = useState<Detection[]>([]);
  const [selected, setSelected] = useState<Detection | null>(null);
  const [noteInput, setNoteInput] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [feedbackMessage, setFeedbackMessage] = useState<string | null>(null);

  useEffect(() => {
    fetchDetections();
    // No auto-refresh - data loads once on mount
  }, []);

  const fetchDetections = async () => {
    try {
      setError(null);
      const data = await api.getDetections({
        page: 1,
        page_size: 20
      });

      const formatted = data.detections.map(api.formatDetectionForFrontend);
      setDetections(formatted);
      setLoading(false);
    } catch (err: any) {
      console.error("Error fetching detections:", err);
      setError(err.message || "Failed to fetch detections");
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "Critical":
        return "text-red-600 font-semibold";
      case "High":
        return "text-orange-500 font-semibold";
      case "Medium":
        return "text-yellow-500 font-semibold";
      case "Low":
        return "text-green-500 font-semibold";
      default:
        return "text-gray-500";
    }
  };

  const handleSaveNote = () => {
    if (!selected) return;
    setDetections((prev) =>
      prev.map((d) =>
        d.id === selected.id ? { ...d, notes: noteInput } : d
      )
    );
    setSelected({ ...selected, notes: noteInput });
    setFeedbackMessage(" Note saved locally");
    setTimeout(() => setFeedbackMessage(null), 2000);
  };

  const handleSubmitFeedback = async (label: 'ATTACK' | 'BENIGN') => {
    if (!selected || !selected.raw) return;

    try {
      await api.submitFeedback({
        detection_id: selected.raw.detection_id,
        label,
        note: noteInput,
        user: "analyst@security.local"
      });

      const labelText = label === 'ATTACK' ? 'Confirmed as Attack' : 'Marked as Safe';

      // Remove detection from list after ANY feedback
      setDetections(prev => prev.filter(d => d.id !== selected.id));
      setFeedbackMessage(` ${labelText} - Detection removed from list`);
      setSelected(null);
      setTimeout(() => setFeedbackMessage(null), 3000);
    } catch (err: any) {
      setFeedbackMessage(` Error: ${err.message}`);
      setTimeout(() => setFeedbackMessage(null), 3000);
    }
  };

  if (loading) {
    return (
      <main className="min-h-screen bg-gray-900 p-8 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-16 w-16 border-t-2 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-xl text-gray-300">Loading detections...</p>
        </div>
      </main>
    );
  }

  if (error) {
    return (
      <main className="min-h-screen bg-gray-900 p-8 flex items-center justify-center">
        <div className="text-center bg-red-900/20 border border-red-500/50 rounded-lg p-8 max-w-lg">
          <p className="text-2xl text-red-400 mb-4"> Error</p>
          <p className="text-gray-300 mb-4">{error}</p>
          <button
            onClick={() => {
              setLoading(true);
              fetchDetections();
            }}
            className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded"
          >
            Retry
          </button>
        </div>
      </main>
    );
  }

  return (
    <main className="min-h-screen bg-gray-900 p-8">
      <div className="flex justify-between items-center mb-2">
        <h1 className="text-3xl font-bold text-gray-100">
          Detection Management
        </h1>
        <div className="flex items-center gap-2">
          <div className="h-3 w-3 bg-green-500 rounded-full animate-pulse"></div>
          <span className="text-sm text-gray-400">
            {detections.length} detections loaded
          </span>
        </div>
      </div>

      <p className="text-gray-400 mb-6">
        View detailed logs, alerts, and submit feedback for each detection.
      </p>

      {feedbackMessage && (
        <div className={`mb-4 p-3 rounded ${feedbackMessage.startsWith('✓')
          ? 'bg-green-900/30 text-green-400 border border-green-500/50'
          : 'bg-red-900/30 text-red-400 border border-red-500/50'
          }`}>
          {feedbackMessage}
        </div>
      )}

      {detections.length === 0 ? (
        <div className="bg-gray-800 rounded-lg shadow-lg p-12 text-center">
          <p className="text-xl text-gray-400 mb-4">No detections found</p>
          <p className="text-gray-500">
            Make predictions to see detections appear here.
          </p>
        </div>
      ) : (
        <div className="bg-gray-800 rounded-lg shadow-lg overflow-hidden">
          <table className="w-full text-sm text-gray-300">
            <thead className="bg-gray-900/50 border-b border-gray-700 text-gray-400">
              <tr>
                <th className="text-left px-4 py-3">ID</th>
                <th className="text-left px-4 py-3">Title</th>
                <th className="text-left px-4 py-3">Severity</th>
                <th className="text-left px-4 py-3">Status</th>
                <th className="text-left px-4 py-3">Timestamp</th>
                <th className="text-left px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {detections.map((d) => (
                  <tr
                  key={d.id}
                  className="border-b border-gray-700 hover:bg-gray-700/50 transition"
                >
                  <td className="px-4 py-3 font-mono text-xs">
                    {d.id.substring(0, 8)}...
                  </td>
                  <td className="px-4 py-3 font-medium text-gray-200">{d.title}</td>
                  <td className={`px-4 py-3 ${getSeverityColor(d.severity)}`}>
                    {d.severity}
                  </td>
                  <td
                    className={`px-4 py-3 ${d.status === "Reviewed"
                      ? "text-green-500 font-semibold"
                      : "text-blue-400 font-semibold"
                      }`}
                  >
                    {d.status}
                  </td>
                  <td className="px-4 py-3 text-gray-500">{d.time}</td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => {
                        setSelected(d);
                        setNoteInput(d.notes);
                      }}
                      className="bg-blue-600 hover:bg-blue-700 text-white px-3 py-1 rounded text-sm"
                    >
                      View Details
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Side Panel for Details */}
      {selected && (
        <div className="fixed inset-y-0 right-0 w-full sm:w-[450px] bg-gray-800 shadow-2xl border-l border-gray-700 p-6 overflow-y-auto transition-transform duration-300 ease-in-out z-50">
          <div className="flex justify-between items-start mb-4">
            <h2 className="text-xl font-bold text-gray-100">
              Detection Details
            </h2>
            <button
              onClick={() => setSelected(null)}
              className="text-gray-400 hover:text-gray-200 text-2xl"
            >
              
            </button>
          </div>

          {/* Detection Details */}
          <div className="space-y-2 text-gray-300 mb-6">
            <p>
              <strong>ID:</strong> <span className="font-mono text-xs">{selected.id}</span>
            </p>
            <p>
              <strong>Title:</strong> {selected.title}
            </p>
            <p>
              <strong>Severity:</strong>{" "}
              <span className={getSeverityColor(selected.severity)}>
                {selected.severity}
              </span>
            </p>
            <p>
              <strong>Status:</strong>{" "}
              <span
                className={
                  selected.status === "Reviewed"
                    ? "text-green-600 font-semibold"
                    : "text-blue-600 font-semibold"
                }
              >
                {selected.status}
              </span>
            </p>
            <p>
              <strong>Timestamp:</strong> {selected.time}
            </p>
          </div>

          {/* Why Attack Was Detected (Real Data) */}
          {selected.raw?.why_detected && selected.raw.why_detected.length > 0 && (
            <div className="mb-6 bg-gray-900/50 border border-gray-700 rounded-lg p-4">
              <h3 className="text-md font-bold text-gray-200 mb-2">
                Why This Attack Was Detected:
              </h3>
              <ul className="list-disc list-inside text-sm text-gray-300 space-y-1">
                {selected.raw.why_detected.map((reason: string, i: number) => (
                  <li key={i}>{reason}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Normal vs Observed Comparison Table (Real Data) */}
          {selected.raw?.feature_comparison && selected.raw.feature_comparison.length > 0 && (
            <div className="mb-6 bg-gray-900/50 border border-gray-700 rounded-lg p-4">
              <h3 className="text-md font-bold text-gray-200 mb-3">
                Normal vs Observed Traffic:
              </h3>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-700 text-gray-400">
                      <th className="text-left py-2 px-1 font-semibold">Feature</th>
                      <th className="text-right py-2 px-1 font-semibold">Normal</th>
                      <th className="text-right py-2 px-1 font-semibold">Observed</th>
                      <th className="text-center py-2 px-1 font-semibold">Deviation</th>
                    </tr>
                  </thead>
                  <tbody>
                    {selected.raw.feature_comparison.map((comp: any, i: number) => (
                      <tr key={i} className="border-b border-gray-800/50">
                        <td className="py-2 px-1 text-gray-300">{comp.feature}</td>
                        <td className="py-2 px-1 text-right text-gray-400">
                          {comp.normal_value} {comp.unit}
                        </td>
                        <td className="py-2 px-1 text-right text-gray-200 font-medium">
                          {comp.observed_value} {comp.unit}
                        </td>
                        <td className="py-2 px-1 text-center text-gray-300">
                          {comp.is_abnormal ? `${comp.multiplier}x` : 'OK'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* IP Reputation Card (Honeypot Integration) */}
          {selected.raw?.ip_reputation && (
            <div className="mb-6 bg-gray-900/50 border border-gray-700 rounded-lg p-4">
              <h3 className="text-md font-bold text-gray-200 mb-3 flex items-center">
                🛡️ &nbsp; IP Threat Intelligence
              </h3>

              <div className="space-y-3">
                {/* IP Address */}
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-400">Source IP:</span>
                  <span className="text-sm font-mono font-semibold text-gray-200">
                    {selected.raw.ip_address}
                  </span>
                </div>

                {/* Threat Level Badge */}
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-400">Threat Level:</span>
                  <span className={`px-3 py-1 rounded-full text-xs font-bold ${selected.raw.ip_reputation.threat_level === 'Critical' ? 'bg-red-100 text-red-800' :
                    selected.raw.ip_reputation.threat_level === 'High' ? 'bg-orange-100 text-orange-800' :
                      selected.raw.ip_reputation.threat_level === 'Medium' ? 'bg-yellow-100 text-yellow-800' :
                        selected.raw.ip_reputation.threat_level === 'Low' ? 'bg-blue-100 text-blue-800' :
                          'bg-green-100 text-green-800'
                    }`}>
                    {selected.raw.ip_reputation.threat_level}
                  </span>
                </div>

                {/* Threat Score */}
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-400">Threat Score:</span>
                  <div className="flex items-center gap-2">
                    <div className="w-32 bg-gray-700 rounded-full h-2">
                      <div
                        className={`h-2 rounded-full ${selected.raw.ip_reputation.threat_score >= 200 ? 'bg-red-600' :
                          selected.raw.ip_reputation.threat_score >= 100 ? 'bg-orange-500' :
                            selected.raw.ip_reputation.threat_score >= 50 ? 'bg-yellow-500' :
                              'bg-green-500'
                          }`}
                        style={{ width: `${(selected.raw.ip_reputation.threat_score / 255) * 100}%` }}
                      ></div>
                    </div>
                    <span className="text-sm font-semibold text-gray-200">
                      {selected.raw.ip_reputation.threat_score}/255
                    </span>
                  </div>
                </div>

                {/* Visitor Types */}
                {selected.raw.ip_reputation.visitor_types && selected.raw.ip_reputation.visitor_types.length > 0 && (
                  <div className="flex justify-between items-start">
                    <span className="text-sm text-gray-400">Activity Type:</span>
                    <div className="flex flex-wrap gap-1 justify-end max-w-xs">
                      {selected.raw.ip_reputation.visitor_types.map((type: string, i: number) => (
                        <span key={i} className="px-2 py-1 bg-purple-900/30 text-purple-400 border border-purple-500/30 rounded text-xs">
                          {type}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Last Activity */}
                {selected.raw.ip_reputation.days_since_activity !== null && (
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-gray-400">Last Seen:</span>
                    <span className="text-sm text-gray-200">
                      {selected.raw.ip_reputation.days_since_activity === 0 ? 'Today' :
                        selected.raw.ip_reputation.days_since_activity === 1 ? 'Yesterday' :
                          `${selected.raw.ip_reputation.days_since_activity} days ago`}
                    </span>
                  </div>
                )}

                {/* Combined Risk Score */}
                {selected.raw.combined_risk_score && selected.raw.combined_risk_score !== selected.raw.risk_score && (
                  <div className="mt-3 pt-3 border-t border-gray-700">
                    <div className="flex justify-between items-center">
                      <span className="text-sm font-semibold text-gray-300">Combined Risk:</span>
                      <span className="text-sm font-bold text-red-400">
                        {(selected.raw.combined_risk_score * 100).toFixed(1)}%
                      </span>
                    </div>
                    <p className="text-xs text-gray-500 mt-1">
                      ML Detection + IP Reputation
                    </p>
                  </div>
                )}

                {/* Recommendation */}
                {selected.raw.ip_reputation.is_threat && (
                  <div className="mt-3 p-2 bg-red-900/20 border border-red-500/30 rounded">
                    <p className="text-xs font-semibold text-red-400">
                      ⚠️ Recommendation: Block this IP immediately
                    </p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Alerts */}
          <div className="mt-6">
            <h3 className="text-md font-semibold text-pink-600 mb-2 flex items-center">
              🎯 &nbsp; Key Features
            </h3>
            <ul className="list-disc list-inside text-gray-300 space-y-1 text-sm">
              {selected.alerts.map((a, i) => (
                <li key={i}>{a}</li>
              ))}
            </ul>
          </div>



          {/* Analyst Feedback Section */}
          <div className="mt-6">
            <h3 className="text-md font-semibold text-purple-600 mb-2 flex items-center">
              👨‍💼 &nbsp; Analyst Feedback
            </h3>
            <p className="text-xs text-gray-400 mb-3">
              Review this detection and provide your expert analysis
            </p>
            <textarea
              value={noteInput}
              onChange={(e) => setNoteInput(e.target.value)}
              placeholder="Add your analysis notes here... (e.g., 'Verified as SQL injection attack' or 'False positive - legitimate traffic')..."
              className="w-full p-3 rounded bg-gray-900/50 border border-gray-700 focus:ring-2 focus:ring-cyan-500 text-gray-200 placeholder-gray-500"
              rows={3}
            />

            {/* Main Actions */}
            <div className="space-y-2 mt-3">
              <div className="grid grid-cols-2 gap-2">
                <button
                  onClick={() => handleSubmitFeedback('ATTACK')}
                  className="bg-red-600 hover:bg-red-700 text-white px-4 py-3 rounded shadow font-semibold flex items-center justify-center gap-2"
                >
                  <span>🚨</span>
                  <span>Confirm Attack</span>
                </button>
                <button
                  onClick={() => handleSubmitFeedback('BENIGN')}
                  className="bg-green-600 hover:bg-green-700 text-white px-4 py-3 rounded shadow font-semibold flex items-center justify-center gap-2"
                >
                  <span>✅</span>
                  <span>Not an Attack</span>
                </button>
              </div>

              {/* False Alert Button */}
              <button
                onClick={() => {
                  if (window.confirm('Mark this as a false alert and remove from list?')) {
                    setDetections(prev => prev.filter(d => d.id !== selected.id));
                    setFeedbackMessage(' False alert removed from list');
                    setSelected(null);
                    setTimeout(() => setFeedbackMessage(null), 3000);
                  }
                }}
                className="w-full bg-orange-600 hover:bg-orange-700 text-white px-4 py-2 rounded shadow font-semibold flex items-center justify-center gap-2"
              >
                <span>⚠️</span>
                <span>Mark as False Alert & Remove</span>
              </button>

              {/* Save Note */}
              <button
                onClick={handleSaveNote}
                className="w-full bg-cyan-600 hover:bg-cyan-700 text-white px-4 py-2 rounded shadow font-medium flex items-center justify-center gap-2"
              >
                <span>💾</span>
                <span>Save Analysis Notes</span>
              </button>
            </div>

            {/* Helper Text */}
            <div className="mt-4 p-3 bg-blue-900/20 rounded border border-blue-500/30">
              <p className="text-xs text-blue-300">
                <strong>💡 Analyst Guide:</strong><br />
                • <strong>Confirm Attack:</strong> If this is a real threat<br />
                • <strong>Not an Attack:</strong> If this is safe/legitimate traffic<br />
                • <strong>False Alert:</strong> Remove incorrect detections from the list
              </p>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}
