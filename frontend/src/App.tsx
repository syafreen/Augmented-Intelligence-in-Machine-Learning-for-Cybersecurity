import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { useEffect } from 'react';
import Sidebar from './components/Sidebar';
import Navbar from './components/Navbar';
import ProtectedRoute from './components/ProtectedRoute';
import Dashboard from './pages/Dashboard';
import Detection from './pages/Detection';
import Honeypot from './pages/Honeypot';
import Login from './pages/Login';
import { isAuthenticated, verifyToken, removeToken } from './services/api';

function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <div className="flex-1 flex flex-col">
        <Navbar />
        {children}
      </div>
    </div>
  );
}

function App() {
  // Validate token on app startup
  useEffect(() => {
    const validateSession = async () => {
      if (isAuthenticated()) {
        try {
          await verifyToken();
          // Token is valid
        } catch (err) {
          // Token invalid or backend restarted - clear and force login
          removeToken();
          window.location.href = '/login';
        }
      }
    };
    validateSession();
  }, []);

  return (
    <Router>
      <Routes>
        {/* Public Route - Login */}
        <Route
          path="/login"
          element={isAuthenticated() ? <Navigate to="/" replace /> : <Login />}
        />

        {/* Protected Routes */}
        <Route path="/" element={
          <ProtectedRoute>
            <AppLayout><Dashboard /></AppLayout>
          </ProtectedRoute>
        } />
        <Route path="/incidents" element={
          <ProtectedRoute>
            <AppLayout><Detection /></AppLayout>
          </ProtectedRoute>
        } />

        <Route path="/honeypot" element={
          <ProtectedRoute>
            <AppLayout><Honeypot /></AppLayout>
          </ProtectedRoute>
        } />

        {/* Catch all - redirect to dashboard or login */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Router>
  );
}

export default App;
