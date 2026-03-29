import { useEffect, useState } from "react";
import {
  ResponsiveContainer,
  Tooltip,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  BarChart,
  Bar,
} from "recharts";
import * as api from "../services/api";

interface ThreatLog {
  id: string;
  type: string;
  confidence: number;
  time: string;
  severity: string;
}

export default function Dashboard() {
  const [stats, setStats] = useState({
    totalFlows: 0,
    totalAttacks: 0,
    benign: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  });

  const [threatHistory, setThreatHistory] = useState<any[]>([]);
  const [logs, setLogs] = useState<ThreatLog[]>([]);
  const [alert, setAlert] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [attackTypes, setAttackTypes] = useState<any[]>([]);

  // Map severity to colors
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'Critical': return '#ef4444';  // Red
      case 'High': return '#f97316';      // Orange
      case 'Medium': return '#f59e0b';    // Yellow
      case 'Low': return '#3b82f6';       // Blue
      case 'Safe':
      default: return '#10b981';          // Green (Benign)
    }
  };

  // Fetch real data from backend (NO auto-refresh)
  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        setError(null);

        // Get detections and metrics from backend
        const detectionsData = await api.getDetections({
          page: 1,
          page_size: 20
        });

        // Calculate stats from real data
        const calculatedStats = api.calculateStats(detectionsData.detections);
        setStats(calculatedStats);

        // Build attack type distribution from detections (group by attack type)
        const attackDetections = detectionsData.detections.filter(d => d.prediction === 'ATTACK');
        if (attackDetections.length > 0) {
          const attackTypeCounts: { [key: string]: number } = {};
          attackDetections.forEach((d: any) => {
            const attackType = d.attack_type || 'Unknown';
            attackTypeCounts[attackType] = (attackTypeCounts[attackType] || 0) + 1;
          });
          const attackTypeData = Object.entries(attackTypeCounts).map(
            ([name, value]) => ({ name, value })
          );
          setAttackTypes(attackTypeData);
        } else {
          setAttackTypes([]);
        }

        // Create logs from recent detections with attack types
        const recentLogs = detectionsData.detections.slice(0, 20).map((d) => ({
          id: d.detection_id,
          type: d.attack_type || d.prediction,
          confidence: Math.round(d.confidence * 100),
          time: new Date(d.timestamp).toLocaleTimeString(),
          severity: d.severity,
        }));
        setLogs(recentLogs);

        // Build threat history (group detections by time intervals)
        const timeMap: { [key: string]: number } = {};

        detectionsData.detections.forEach((d) => {
          const timeKey = new Date(d.timestamp).toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit"
          });

          // Count only attacks, not benign
          if (d.prediction === 'ATTACK') {
            timeMap[timeKey] = (timeMap[timeKey] || 0) + 1;
          } else {
            // Ensure time exists even if no attacks
            if (!timeMap[timeKey]) {
              timeMap[timeKey] = 0;
            }
          }
        });

        // Convert to chart format and sort by time
        const history = Object.entries(timeMap)
          .map(([time, threats]) => ({ time, threats }))
          .slice(0, 10); // Show last 10 time points

        setThreatHistory(history.length > 0 ? history : [{ time: "Now", threats: 0 }]);

        // Show alert for high-risk detections
        const criticalCount = detectionsData.detections.filter(
          d => d.severity === 'Critical'
        ).length;

        if (criticalCount > 0) {
          setAlert(`🚨 ALERT: ${criticalCount} critical threats detected!`);
          setTimeout(() => setAlert(null), 5000);
        }

        setLoading(false);
      } catch (err: any) {
        console.error("Error fetching data:", err);
        setError(err.message || "Failed to fetch data");
        setLoading(false);
      }
    };

    fetchData();
    // No auto-refresh - data loads once on mount
  }, []);

  // Build attack distribution for pie chart (group by attack_type + severity)
  const attackDistribution: any[] = [];

  // Add Benign first
  if (stats.benign > 0) {
    attackDistribution.push({
      name: "BENIGN",
      value: stats.benign,
      fullName: "Benign Traffic",
      severity: "Safe"
    });
  }

  // Group attacks by type + severity
  const attackTypeMap: { [key: string]: number } = {};
  const attackMetadata: { [key: string]: { type: string, severity: string } } = {};

  logs.filter(log => log.type !== 'BENIGN').forEach(log => {
    const key = `${log.type} (${log.severity})`;
    attackTypeMap[key] = (attackTypeMap[key] || 0) + 1;
    attackMetadata[key] = { type: log.type, severity: log.severity };
  });

  // Add to distribution
  Object.entries(attackTypeMap).forEach(([key, value]) => {
    const meta = attackMetadata[key];
    attackDistribution.push({
      name: key,
      value: value,
      fullName: `${meta.type} - ${meta.severity} Severity`,
      severity: meta.severity
    });
  });

  // Build data for stacked bar chart
  const barChartData: any[] = [];
  const typeGroups: { [key: string]: { [severity: string]: number } } = {};

  // Add BENIGN
  if (stats.benign > 0) {
    barChartData.push({
      name: "BENIGN",
      Safe: stats.benign,
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0
    });
  }

  // Group attacks by type and severity
  logs.filter(log => log.type !== 'BENIGN').forEach(log => {
    const type = log.type;
    const severity = log.severity;

    if (!typeGroups[type]) {
      typeGroups[type] = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    }
    typeGroups[type][severity] = (typeGroups[type][severity] || 0) + 1;
  });

  // Convert to bar chart format
  Object.entries(typeGroups).forEach(([type, severities]) => {
    barChartData.push({
      name: type,
      Safe: 0,
      ...severities
    });
  });

  if (loading && stats.totalFlows === 0) {
    return (
      <main className="min-h-screen bg-gray-900 text-gray-100 p-8 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-16 w-16 border-t-2 border-b-2 border-cyan-400 mx-auto mb-4"></div>
          <p className="text-xl text-cyan-400">Loading dashboard data...</p>
          <p className="text-sm text-gray-400 mt-2">Connecting to backend...</p>
        </div>
      </main>
    );
  }

  if (error) {
    return (
      <main className="min-h-screen bg-gray-900 text-gray-100 p-8 flex items-center justify-center">
        <div className="text-center bg-red-900/20 border border-red-500 rounded-lg p-8 max-w-lg">
          <p className="text-2xl text-red-400 mb-4">❌ Connection Error</p>
          <p className="text-gray-300 mb-4">{error}</p>
          <p className="text-sm text-gray-400">
            Make sure the backend service is running and reachable.
          </p>
          <button
            onClick={() => window.location.reload()}
            className="mt-4 bg-cyan-600 hover:bg-cyan-700 text-white px-6 py-2 rounded"
          >
            Retry
          </button>
        </div>
      </main>
    );
  }

  return (
    <main className="min-h-screen bg-gray-900 text-gray-100 p-8">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-3xl font-bold text-cyan-400">
          Real-Time Threat Dashboard
        </h1>
        <div className="flex items-center gap-2">
          <div className="h-3 w-3 bg-green-500 rounded-full animate-pulse"></div>
          <span className="text-sm text-gray-400">Live from Backend</span>
        </div>
      </div>

      {/* 🚨 Alert Banner */}
      {alert && (
        <div className="animate-pulse bg-red-600 text-white text-center py-2 rounded-lg mb-4 font-semibold shadow-lg">
          {alert}
        </div>
      )}

      {/* Main Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <StatCard title="Total Network Flows" value={stats.totalFlows} color="text-blue-400" />
        <StatCard title="Total Attacks" value={stats.totalAttacks} color="text-red-400" />
        <StatCard title="Benign" value={stats.benign} color="text-green-400" />
        <StatCard title="Critical" value={stats.critical} color="text-red-600" />
        <StatCard title="High Risk" value={stats.high} color="text-orange-400" />
        <StatCard title="Medium Risk" value={stats.medium} color="text-yellow-400" />
        <StatCard title="Low Risk" value={stats.low} color="text-blue-300" />
      </div>

      {/* 🎯 Attack Types Distribution */}
      {attackTypes.length > 0 && (
        <div className="bg-gray-800 rounded-lg shadow-lg p-6 mb-6">
          <h2 className="text-lg font-semibold text-center text-cyan-400 mb-4">
            Attack Types Detected
          </h2>
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-7 gap-3">
            {attackTypes.map((type) => (
              <div key={type.name} className="bg-gray-700/50 p-3 rounded-lg text-center border border-gray-600 hover:border-red-500 transition">
                <p className="text-xs text-gray-400 mb-1">{type.name}</p>
                <p className="text-xl font-bold text-red-400">{type.value}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 📊 Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        {/* Attack Distribution Stacked Bar Chart */}
        <div className="bg-gray-800 rounded-lg shadow-lg p-6">
          <h2 className="text-lg font-semibold text-center text-cyan-400 mb-4">
            Attack Distribution
          </h2>
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={barChartData} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis type="number" stroke="#9ca3af" />
                <YAxis dataKey="name" type="category" stroke="#9ca3af" width={100} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#1f2937",
                    color: "#fff",
                    border: "1px solid #374151",
                    borderRadius: "8px",
                    padding: "10px"
                  }}
                />
                <Bar dataKey="Safe" stackId="a" fill={getSeverityColor('Safe')} />
                <Bar dataKey="Low" stackId="a" fill={getSeverityColor('Low')} />
                <Bar dataKey="Medium" stackId="a" fill={getSeverityColor('Medium')} />
                <Bar dataKey="High" stackId="a" fill={getSeverityColor('High')} />
                <Bar dataKey="Critical" stackId="a" fill={getSeverityColor('Critical')} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Severity Legend */}
          <div className="mt-6 pt-4 border-t border-gray-700">
            <p className="text-sm text-gray-400 text-center mb-3">Severity Levels:</p>
            <div className="flex flex-wrap justify-center gap-4">
              <div className="flex items-center gap-2">
                <div className="w-4 h-4 rounded" style={{ backgroundColor: '#10b981' }}></div>
                <span className="text-xs text-gray-300">Safe (Benign)</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-4 h-4 rounded" style={{ backgroundColor: '#3b82f6' }}></div>
                <span className="text-xs text-gray-300">Low</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-4 h-4 rounded" style={{ backgroundColor: '#f59e0b' }}></div>
                <span className="text-xs text-gray-300">Medium</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-4 h-4 rounded" style={{ backgroundColor: '#f97316' }}></div>
                <span className="text-xs text-gray-300">High</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-4 h-4 rounded" style={{ backgroundColor: '#ef4444' }}></div>
                <span className="text-xs text-gray-300">Critical</span>
              </div>
            </div>
          </div>
        </div>

        {/* Real-Time Line Chart */}
        <div className="bg-gray-800 rounded-lg shadow-lg p-6">
          <h2 className="text-lg font-semibold text-center text-cyan-400 mb-4">
            Threat Activity Timeline
          </h2>
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={threatHistory}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="time" stroke="#9ca3af" />
                <YAxis stroke="#9ca3af" />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#1f2937",
                    color: "#fff",
                    border: "1px solid #374151",
                  }}
                />
                <Line
                  type="monotone"
                  dataKey="threats"
                  stroke="#06b6d4"
                  strokeWidth={3}
                  dot={{ r: 4, fill: "#06b6d4" }}
                  activeDot={{ r: 6 }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* 🕵️ Live Logs */}
      <div className="bg-gray-800 rounded-lg shadow-lg p-6">
        <h2 className="text-lg font-semibold text-center text-cyan-400 mb-4">
          Recent Detections
        </h2>
        {logs.length === 0 ? (
          <div className="text-center py-8 text-gray-400">
            <p>No detections yet. Waiting for network traffic...</p>
            <p className="text-sm mt-2">Make a prediction to see detections appear here.</p>
          </div>
        ) : (
          <div className="max-h-64 overflow-y-auto">
            <table className="w-full text-sm text-gray-300">
              <thead className="text-gray-400 border-b border-gray-700">
                <tr>
                  <th className="text-left py-2">Type</th>
                  <th className="text-left">Severity</th>
                  <th className="text-left">Confidence</th>
                  <th className="text-left">Time</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((log) => (
                  <tr key={log.id} className="border-b border-gray-800 hover:bg-gray-700/50">
                    <td className={`py-1 font-semibold ${log.type === 'ATTACK' ? 'text-red-400' : 'text-green-400'}`}>
                      {log.type}
                    </td>
                    <td className={`py-1 font-semibold ${log.severity === 'Critical' ? 'text-red-600' :
                      log.severity === 'High' ? 'text-orange-400' :
                        log.severity === 'Medium' ? 'text-yellow-400' : 'text-blue-400'
                      }`}>
                      {log.severity}
                    </td>
                    <td>{log.confidence}%</td>
                    <td className="text-gray-400">{log.time}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </main>
  );
}

interface StatCardProps {
  title: string;
  value: number;
  color: string;
  suffix?: string;
}

function StatCard({ title, value, color, suffix = "" }: StatCardProps) {
  return (
    <div className="bg-gray-800 p-4 rounded-lg text-center shadow-md hover:shadow-lg transition">
      <p className="text-gray-400 text-sm mb-2">{title}</p>
      <p className={`text-3xl font-bold ${color}`}>
        {value}{suffix}
      </p>
    </div>
  );
}
