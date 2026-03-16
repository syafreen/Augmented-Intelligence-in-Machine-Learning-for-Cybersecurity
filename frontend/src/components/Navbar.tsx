import { useNavigate } from 'react-router-dom';
import { logout, getUser } from '../services/api';

export default function Navbar() {
  const navigate = useNavigate();
  const username = getUser();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <header className="bg-gray-800 text-gray-100 px-6 py-3 flex justify-between items-center border-b border-gray-700">
      <h2 className="text-lg font-semibold tracking-wide">Threat Ops</h2>
      <div className="flex items-center gap-4">
        {username && (
          <span className="text-gray-400 text-sm">
            Welcome, <span className="text-cyan-400 font-medium">{username}</span>
          </span>
        )}
        <button
          onClick={handleLogout}
          className="bg-gray-700 hover:bg-red-600 transition px-3 py-1 rounded text-white text-sm flex items-center gap-2"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
          </svg>
          Logout
        </button>
      </div>
    </header>
  );
}
