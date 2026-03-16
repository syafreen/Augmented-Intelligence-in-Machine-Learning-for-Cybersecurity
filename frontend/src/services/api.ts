

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8081/api';

export interface IPReputation {
  ip_address: string;
  is_threat: boolean;
  threat_score: number;
  threat_level: 'Critical' | 'High' | 'Medium' | 'Low' | 'Clean';
  days_since_activity: number | null;
  visitor_types: string[];
  visitor_type_code: number;
  raw_response: string | null;
}

export interface Detection {
  detection_id: string;
  timestamp: string;
  prediction: 'ATTACK' | 'BENIGN';
  attack_type: string;
  risk_score: number;
  confidence: number;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';

  explanation?: Array<{
    feature: string;
    value: number | string;
    contribution: number;
  }>;

  // Honeypot integration
  ip_address?: string;
  ip_reputation?: IPReputation | null;
  combined_risk_score?: number;
}

export interface LoginAttempt {
  id: string;
  timestamp: string;
  username: string;
  ip_address: string;
  success: boolean;
  ip_reputation?: IPReputation | null;
}


export interface DetectionsListResponse {
  detections: Detection[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface FeedbackRequest {
  detection_id: string;
  label: 'ATTACK' | 'BENIGN' | 'Unknown';
  note?: string;
  user?: string;
}

export interface MetricsResponse {
  total_labeled: number;
  accuracy: number;
  precision: number;
  recall: number;
  f1_score: number;
  roc_auc?: number;
  pr_auc?: number;
  confusion_matrix: {
    TP: number;
    TN: number;
    FP: number;
    FN: number;
  };
  per_class: {
    ATTACK: {
      precision: number;
      recall: number;
      f1_score: number;
      support: number;
    };
    BENIGN: {
      precision: number;
      recall: number;
      f1_score: number;
      support: number;
    };
  };
  severity_trends: {
    by_date: Array<{
      date: string;
      critical: number;
      high: number;
      medium: number;
      low: number;
      total: number;
    }>;
    overall_distribution: {
      [key: string]: number;
    };
  };
  global_shap: Array<{
    feature: string;
    mean_abs_contribution: number;
    std_contribution: number;
    count: number;
  }>;
  metadata?: {
    labeled_detections: number;
    shap_window_size: number;
    detections_with_shap: number;
  };
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  success: boolean;
  token: string;
  username: string;
  expires_in: number;
}

export interface HealthCheckResponse {
  status: string;
  models_loaded: {
    random_forest: boolean;
    xgboost: boolean;
    isolation_forest: boolean;
  };
  shap_available: boolean;
  data_loaded: boolean;
  timestamp: string;
}

export interface FeedbackResponse {
  detection_id: string;
  label: string;
  note: string;
  user: string;
  timestamp: string;
  feedback_id: string;
}

const TOKEN_KEY = 'ids_token';
const USER_KEY = 'ids_user';

export function getToken(): string | null {
  return sessionStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  sessionStorage.setItem(TOKEN_KEY, token);
}

export function removeToken(): void {
  sessionStorage.removeItem(TOKEN_KEY);
  sessionStorage.removeItem(USER_KEY);
}

export function getUser(): string | null {
  return sessionStorage.getItem(USER_KEY);
}

export function setUser(username: string): void {
  sessionStorage.setItem(USER_KEY, username);
}

export function isAuthenticated(): boolean {
  return !!getToken();
}

function getAuthHeaders(): HeadersInit {
  const token = getToken();
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

/**
 * Login to the system
 */
export async function login(credentials: LoginRequest): Promise<LoginResponse> {
  const response = await fetch(`${API_BASE_URL}/auth/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(credentials),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error || 'Login failed');
  }

  const data = await response.json();

  // Store token and user
  if (data.token) {
    setToken(data.token);
    setUser(data.username);
  }

  return data;
}

/**
 * Logout from the system
 */
export async function logout(): Promise<void> {
  try {
    await fetch(`${API_BASE_URL}/auth/logout`, {
      method: 'POST',
      headers: getAuthHeaders(),
    });
  } catch (e) {
    // Ignore errors, just clear local storage
  }
  removeToken();
}

/**
 * Verify if current token is valid
 */
export async function verifyToken(): Promise<boolean> {
  const token = getToken();
  if (!token) return false;

  try {
    const response = await fetch(`${API_BASE_URL}/auth/verify`, {
      headers: getAuthHeaders(),
    });
    return response.ok;
  } catch {
    return false;
  }
}


/**
 * Get list of detections with optional filters
 */
export async function getDetections(params?: {
  page?: number;
  page_size?: number;
  severity?: string;
  prediction?: string;
  min_risk_score?: number;
  max_risk_score?: number;
}): Promise<DetectionsListResponse> {
  const queryParams = new URLSearchParams();

  if (params) {
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined) {
        queryParams.append(key, String(value));
      }
    });
  }

  const url = `${API_BASE_URL}/detections${queryParams.toString() ? '?' + queryParams.toString() : ''}`;
  const response = await fetch(url);

  if (!response.ok) {
    throw new Error('Failed to fetch detections');
  }

  return response.json();
}

/**
 * Get detection by ID with feedback history
 */
export async function getDetectionById(id: string): Promise<{ detection: Detection; feedback: FeedbackResponse[] }> {
  const response = await fetch(`${API_BASE_URL}/detections/${id}`);

  if (!response.ok) {
    throw new Error('Detection not found');
  }

  const data = await response.json();
  // Backend returns { detection: {...}, feedback: [...] }
  return data;
}

/**
 * Submit feedback for a detection
 */
export async function submitFeedback(data: FeedbackRequest): Promise<{ feedback_id: string }> {
  const response = await fetch(`${API_BASE_URL}/feedback`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(data),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error || 'Failed to submit feedback');
  }

  return response.json();
}

/**
 * Get model performance metrics
 */
export async function getMetrics(): Promise<MetricsResponse> {
  const response = await fetch(`${API_BASE_URL}/analytics/metrics`);

  if (!response.ok) {
    throw new Error('Failed to fetch metrics');
  }

  return response.json();
}


/**
 * Health check
 */
export async function checkHealth(): Promise<HealthCheckResponse> {
  const response = await fetch(`${API_BASE_URL}/health`);

  if (!response.ok) {
    throw new Error('Health check failed');
  }

  return response.json();
}

/**
 * Map backend severity to frontend expectations
 */
export function mapSeverity(severity: string): 'Critical' | 'High' | 'Medium' | 'Low' {
  const normalized = severity.toLowerCase();
  if (normalized === 'critical') return 'Critical';
  if (normalized === 'high') return 'High';
  if (normalized === 'medium') return 'Medium';
  return 'Low';
}

/**
 * Get attack statistics from detections
 */
export function calculateStats(detections: Detection[]) {
  const stats = {
    totalFlows: detections.length,
    totalAttacks: detections.filter(d => d.prediction === 'ATTACK').length,
    benign: detections.filter(d => d.prediction === 'BENIGN').length,
    critical: detections.filter(d => d.severity === 'Critical').length,
    high: detections.filter(d => d.severity === 'High').length,
    medium: detections.filter(d => d.severity === 'Medium').length,
    low: detections.filter(d => d.severity === 'Low').length,
  };

  return stats;
}

/**
 * Format detection for frontend display
 */
export function formatDetectionForFrontend(detection: Detection) {
  // Use attack_type if available, otherwise use prediction
  const displayType = (detection as any).attack_type || detection.prediction;

  return {
    id: detection.detection_id,
    title: `${displayType} detected`,
    severity: mapSeverity(detection.severity),
    status: 'Open',
    time: new Date(detection.timestamp).toLocaleString(),
    alerts: detection.explanation
      ? detection.explanation
        .slice(0, 3)
        .map(e => `Feature "${e.feature}": ${e.value} (contribution: ${e.contribution.toFixed(4)})`)
      : [`${displayType} prediction with ${(detection.risk_score * 100).toFixed(1)}% risk score`],
    logs: [
      `${new Date(detection.timestamp).toLocaleTimeString()} — Detection created`,
      `Attack Type: ${displayType}`,
    ],
    notes: '',
    raw: detection,
  };
}

export default {
  getDetections,
  getDetectionById,
  submitFeedback,
  getMetrics,
  checkHealth,
  calculateStats,
  formatDetectionForFrontend,
};


export interface HoneypotStatsResponse {
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
    malicious_ips: any[];
  };
  login_monitoring: {
    total_attempts: number;
    failed_attempts: number;
    successful_logins: number;
    recent_attempts: any[];
  };
  honeypot_status: {
    enabled: boolean;
    api_key_configured: boolean;
    cache_size: number;
  };
}

export async function getHoneypotStats(): Promise<HoneypotStatsResponse> {
  const token = getToken();
  const response = await fetch(`${API_BASE_URL}/honeypot/stats`, {
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  });

  if (!response.ok) {
    throw new Error('Failed to fetch honeypot statistics');
  }

  return response.json();
}
