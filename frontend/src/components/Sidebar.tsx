import { NavLink } from "react-router-dom";

export default function Sidebar() {
  return (
    <aside className="bg-gray-900 text-gray-100 w-60 min-h-screen p-4">
      <h1 className="text-2xl font-bold text-cyan-400 tracking-wide mb-6">
        SVIT <span className="text-gray-300">— SOC</span>
      </h1>
      <p className="text-xs text-gray-500 mb-6">
        Security Operations Center
      </p>

      <nav className="flex flex-col gap-2">
        <NavLink
          to="/"
          end
          className={({ isActive }) =>
            `block px-4 py-2 rounded-md hover:bg-gray-800 transition ${isActive ? "bg-cyan-600 text-white" : "text-gray-300"
            }`
          }
        >
          Dashboard
        </NavLink>
        <NavLink
          to="/incidents"
          className={({ isActive }) =>
            `block px-4 py-2 rounded-md hover:bg-gray-800 transition ${isActive ? "bg-cyan-600 text-white" : "text-gray-300"
            }`
          }
        >
          Detections
        </NavLink>
        <NavLink
          to="/honeypot"
          className={({ isActive }) =>
            `block px-4 py-2 rounded-md hover:bg-gray-800 transition ${isActive ? "bg-cyan-600 text-white" : "text-gray-300"
            }`
          }
        >
          Honeypot
        </NavLink>
      </nav>
    </aside>
  );
}
