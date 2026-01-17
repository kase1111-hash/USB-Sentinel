/**
 * USB Sentinel Dashboard - Main Application
 *
 * Real-time monitoring dashboard for USB device events,
 * policy management, and security analysis.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom';
import { DeviceList } from './components/DeviceList';
import { EventFeed } from './components/EventFeed';
import { PolicyEditor } from './components/PolicyEditor';
import { Dashboard } from './components/Dashboard';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5000,
      refetchInterval: 10000,
    },
  },
});

function Navigation() {
  return (
    <nav className="bg-gray-900 text-white p-4">
      <div className="container mx-auto flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <span className="text-xl font-bold">USB Sentinel</span>
        </div>
        <div className="flex space-x-6">
          <NavLink
            to="/"
            className={({ isActive }) =>
              isActive ? 'text-blue-400' : 'hover:text-blue-300'
            }
          >
            Dashboard
          </NavLink>
          <NavLink
            to="/devices"
            className={({ isActive }) =>
              isActive ? 'text-blue-400' : 'hover:text-blue-300'
            }
          >
            Devices
          </NavLink>
          <NavLink
            to="/events"
            className={({ isActive }) =>
              isActive ? 'text-blue-400' : 'hover:text-blue-300'
            }
          >
            Events
          </NavLink>
          <NavLink
            to="/policy"
            className={({ isActive }) =>
              isActive ? 'text-blue-400' : 'hover:text-blue-300'
            }
          >
            Policy
          </NavLink>
        </div>
      </div>
    </nav>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <div className="min-h-screen bg-gray-100">
          <Navigation />
          <main className="container mx-auto p-6">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/devices" element={<DeviceList />} />
              <Route path="/events" element={<EventFeed />} />
              <Route path="/policy" element={<PolicyEditor />} />
            </Routes>
          </main>
        </div>
      </BrowserRouter>
    </QueryClientProvider>
  );
}

export default App;
