import { useState, useEffect } from 'react';
import { getHoneypotStats } from '../services/api';

interface HoneypotStats {
  ip_reputation: {
    total_checks: number;
    threats_found: number;
    threat_distribution: {
      critical: number;
      high: number;
      medium: number;
      low: number;
      clean: number;
    };
    malicious_ips: Array<{
      ip: string;
      threat_score: number;
      threat_level: string;
      visitor_types: string[];
    }>;
  };
  login_monitoring: {
    total_attempts: number;
    failed_attempts: number;
    successful_logins: number;
    recent_attempts: Array<{
      id: string;
      timestamp: string;
      username: string;
      ip_address: string;
      success: boolean;
    }>;
  };
  honeypot_status: {
    enabled: boolean;
    api_key_configured: boolean;
    cache_size: number;
  };
}

export default function Honeypot() {
  const [stats, setStats] = useState<HoneypotStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const loadStats = async () => {
    try {
      setLoading(true);
      const data = await getHoneypotStats();
      setStats(data);
      setError('');
    } catch (err: any) {
      setError(err.message || 'Failed to load honeypot statistics');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadStats();
    // Auto-refresh every 5 seconds
    const interval = setInterval(loadStats, 5000);
    return () => clearInterval(interval);
  }, []);

  if (loading && !stats) {
    return (
      <div className="p-6 flex items-center justify-center min-h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyan-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading honeypot statistics...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6">
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <p className="text-red-800">{error}</p>
          <button
            onClick={loadStats}
            className="mt-2 px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  if (!stats) return null;

  const { ip_reputation, login_monitoring } = stats;

  return (
    <div className="p-6 bg-gray-900 min-h-screen text-gray-100">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-3xl font-bold text-gray-100 mb-2">Honeypot Intelligence Dashboard</h1>
        <p className="text-gray-400">Real-time threat intelligence and security monitoring</p>
      </div>


      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-6">
        {/* Total IP Checks */}
        <div className="bg-gray-800 rounded-lg shadow-md p-6 border-l-4 border-blue-500">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-400 mb-1">Total IP Checks</p>
              <p className="text-3xl font-bold text-gray-100">{ip_reputation.total_checks}</p>
            </div>
            <div className="text-4xl">🔍</div>
          </div>
        </div>

        {/* Threats Found */}
        <div className="bg-gray-800 rounded-lg shadow-md p-6 border-l-4 border-red-500">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-400 mb-1">Threats Detected</p>
              <p className="text-3xl font-bold text-red-400">{ip_reputation.threats_found}</p>
            </div>
            <div className="text-4xl">⚠️</div>
          </div>
        </div>

        {/* Login Attempts */}
        <div className="bg-gray-800 rounded-lg shadow-md p-6 border-l-4 border-orange-500">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-400 mb-1">Login Attempts</p>
              <p className="text-3xl font-bold text-gray-100">{login_monitoring.total_attempts}</p>
            </div>
            <div className="text-4xl">🔐</div>
          </div>
        </div>

        {/* Failed Logins */}
        <div className="bg-gray-800 rounded-lg shadow-md p-6 border-l-4 border-yellow-500">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-400 mb-1">Failed Logins</p>
              <p className="text-3xl font-bold text-yellow-500">{login_monitoring.failed_attempts}</p>
            </div>
            <div className="text-4xl">❌</div>
          </div>
        </div>
      </div>

      {/* Threat Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        {/* Threat Level Distribution */}
        <div className="bg-gray-800 rounded-lg shadow-md p-6">
          <h2 className="text-xl font-bold text-gray-100 mb-4">Threat Level Distribution</h2>
          <div className="space-y-3">
            {/* Critical */}
            <div>
              <div className="flex justify-between items-center mb-1">
                <span className="text-sm font-medium text-gray-300">Critical</span>
                <span className="text-sm font-bold text-red-500">{ip_reputation.threat_distribution.critical}</span>
              </div>
              <div className="w-full bg-gray-700 rounded-full h-2">
                <div
                  className="bg-red-600 h-2 rounded-full"
                  style={{ width: `${(ip_reputation.threat_distribution.critical / ip_reputation.total_checks) * 100}%` }}
                ></div>
              </div>
            </div>

            {/* High */}
            <div>
              <div className="flex justify-between items-center mb-1">
                <span className="text-sm font-medium text-gray-300">High</span>
                <span className="text-sm font-bold text-orange-500">{ip_reputation.threat_distribution.high}</span>
              </div>
              <div className="w-full bg-gray-700 rounded-full h-2">
                <div
                  className="bg-orange-500 h-2 rounded-full"
                  style={{ width: `${(ip_reputation.threat_distribution.high / ip_reputation.total_checks) * 100}%` }}
                ></div>
              </div>
            </div>

            {/* Medium */}
            <div>
              <div className="flex justify-between items-center mb-1">
                <span className="text-sm font-medium text-gray-300">Medium</span>
                <span className="text-sm font-bold text-yellow-500">{ip_reputation.threat_distribution.medium}</span>
              </div>
              <div className="w-full bg-gray-700 rounded-full h-2">
                <div
                  className="bg-yellow-500 h-2 rounded-full"
                  style={{ width: `${(ip_reputation.threat_distribution.medium / ip_reputation.total_checks) * 100}%` }}
                ></div>
              </div>
            </div>

            {/* Low */}
            <div>
              <div className="flex justify-between items-center mb-1">
                <span className="text-sm font-medium text-gray-300">Low</span>
                <span className="text-sm font-bold text-blue-500">{ip_reputation.threat_distribution.low}</span>
              </div>
              <div className="w-full bg-gray-700 rounded-full h-2">
                <div
                  className="bg-blue-500 h-2 rounded-full"
                  style={{ width: `${(ip_reputation.threat_distribution.low / ip_reputation.total_checks) * 100}%` }}
                ></div>
              </div>
            </div>

            {/* Clean */}
            <div>
              <div className="flex justify-between items-center mb-1">
                <span className="text-sm font-medium text-gray-300">Clean</span>
                <span className="text-sm font-bold text-green-500">{ip_reputation.threat_distribution.clean}</span>
              </div>
              <div className="w-full bg-gray-700 rounded-full h-2">
                <div
                  className="bg-green-500 h-2 rounded-full"
                  style={{ width: `${(ip_reputation.threat_distribution.clean / ip_reputation.total_checks) * 100}%` }}
                ></div>
              </div>
            </div>
          </div>
        </div>

        {/* Login Success Rate */}
        <div className="bg-gray-800 rounded-lg shadow-md p-6">
          <h2 className="text-xl font-bold text-gray-100 mb-4">Login Activity</h2>
          <div className="space-y-4">
            <div className="flex justify-between items-center p-4 bg-green-900/20 border border-green-500/30 rounded-lg">
              <div>
                <p className="text-sm text-gray-400">Successful Logins</p>
                <p className="text-2xl font-bold text-green-400">{login_monitoring.successful_logins}</p>
              </div>
              <div className="text-3xl">✅</div>
            </div>
            <div className="flex justify-between items-center p-4 bg-red-900/20 border border-red-500/30 rounded-lg">
              <div>
                <p className="text-sm text-gray-400">Failed Attempts</p>
                <p className="text-2xl font-bold text-red-500">{login_monitoring.failed_attempts}</p>
              </div>
              <div className="text-3xl">🚫</div>
            </div>
            <div className="p-4 bg-gray-700/50 rounded-lg">
              <p className="text-sm text-gray-400 mb-2">Success Rate</p>
              <div className="w-full bg-gray-600 rounded-full h-3">
                <div
                  className="bg-green-500 h-3 rounded-full"
                  style={{
                    width: `${login_monitoring.total_attempts > 0
                      ? (login_monitoring.successful_logins / login_monitoring.total_attempts) * 100
                      : 0}%`
                  }}
                ></div>
              </div>
              <p className="text-xs text-gray-400 mt-1">
                {login_monitoring.total_attempts > 0
                  ? ((login_monitoring.successful_logins / login_monitoring.total_attempts) * 100).toFixed(1)
                  : 0}% successful
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Malicious IPs Table */}
      {ip_reputation.malicious_ips.length > 0 && (
        <div className="bg-gray-800 rounded-lg shadow-md p-6 mb-6">
          <h2 className="text-xl font-bold text-gray-100 mb-4">🔴 Top Malicious IPs</h2>
          <div className="overflow-x-auto">
            <table className="min-w-full">
              <thead>
                <tr className="border-b border-gray-700">
                  <th className="text-left py-3 px-4 text-sm font-semibold text-gray-400">IP Address</th>
                  <th className="text-left py-3 px-4 text-sm font-semibold text-gray-400">Threat Level</th>
                  <th className="text-left py-3 px-4 text-sm font-semibold text-gray-400">Threat Score</th>
                  <th className="text-left py-3 px-4 text-sm font-semibold text-gray-400">Activity Types</th>
                </tr>
              </thead>
              <tbody>
                {ip_reputation.malicious_ips.map((ip, index) => (
                  <tr key={index} className="border-b border-gray-700/50 hover:bg-gray-700 transition">
                    <td className="py-3 px-4 font-mono text-sm text-gray-200">{ip.ip}</td>
                    <td className="py-3 px-4">
                      <span className={`px-3 py-1 rounded-full text-xs font-bold ${ip.threat_level === 'Critical' ? 'bg-red-900/50 text-red-400 border border-red-500/30' :
                        ip.threat_level === 'High' ? 'bg-orange-900/50 text-orange-400 border border-orange-500/30' :
                          'bg-yellow-900/50 text-yellow-400 border border-yellow-500/30'
                        }`}>
                        {ip.threat_level}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-sm font-semibold text-gray-200">{ip.threat_score}/255</td>
                    <td className="py-3 px-4">
                      <div className="flex flex-wrap gap-1">
                        {ip.visitor_types.map((type, i) => (
                          <span key={i} className="px-2 py-1 bg-purple-900/30 text-purple-400 border border-purple-500/30 rounded text-xs">
                            {type}
                          </span>
                        ))}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Recent Login Attempts */}
      {login_monitoring.recent_attempts.length > 0 && (
        <div className="bg-gray-800 rounded-lg shadow-md p-6">
          <h2 className="text-xl font-bold text-gray-100 mb-4">📋 Recent Login Attempts</h2>
          <div className="overflow-x-auto">
            <table className="min-w-full">
              <thead>
                <tr className="border-b border-gray-700">
                  <th className="text-left py-3 px-4 text-sm font-semibold text-gray-400">Timestamp</th>
                  <th className="text-left py-3 px-4 text-sm font-semibold text-gray-400">Username</th>
                  <th className="text-left py-3 px-4 text-sm font-semibold text-gray-400">IP Address</th>
                  <th className="text-left py-3 px-4 text-sm font-semibold text-gray-400">Status</th>
                </tr>
              </thead>
              <tbody>
                {login_monitoring.recent_attempts.map((attempt) => (
                  <tr key={attempt.id} className="border-b border-gray-700/50 hover:bg-gray-700 transition">
                    <td className="py-3 px-4 text-sm text-gray-300">
                      {new Date(attempt.timestamp).toLocaleString()}
                    </td>
                    <td className="py-3 px-4 text-sm font-medium text-gray-200">{attempt.username}</td>
                    <td className="py-3 px-4 font-mono text-sm text-gray-300">{attempt.ip_address}</td>
                    <td className="py-3 px-4">
                      <span className={`px-3 py-1 rounded-full text-xs font-bold ${attempt.success
                        ? 'bg-green-900/50 text-green-400 border border-green-500/30'
                        : 'bg-red-900/50 text-red-400 border border-red-500/30'
                        }`}>
                        {attempt.success ? '✓ Success' : '✗ Failed'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
