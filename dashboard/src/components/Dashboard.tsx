/**
 * Dashboard - Main overview page
 *
 * Shows real-time statistics, recent events, and risk overview.
 */

import { useQuery } from '@tanstack/react-query';
import { useWebSocket } from '../hooks/useWebSocket';
import { api } from '../api';

interface Statistics {
  total_devices: number;
  trusted_devices: number;
  blocked_devices: number;
  unknown_devices: number;
  total_events: number;
  events_today: number;
  blocked_today: number;
  allowed_today: number;
}

function StatCard({
  title,
  value,
  color = 'blue',
}: {
  title: string;
  value: number | string;
  color?: string;
}) {
  const colorClasses = {
    blue: 'bg-blue-500',
    green: 'bg-green-500',
    red: 'bg-red-500',
    yellow: 'bg-yellow-500',
    gray: 'bg-gray-500',
  };

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <div className="flex items-center">
        <div className={`${colorClasses[color]} rounded-full p-3 mr-4`}>
          <span className="text-white text-xl">{value}</span>
        </div>
        <div>
          <p className="text-gray-500 text-sm">{title}</p>
          <p className="text-2xl font-bold">{value}</p>
        </div>
      </div>
    </div>
  );
}

export function Dashboard() {
  const { data: stats, isLoading } = useQuery<Statistics>({
    queryKey: ['statistics'],
    queryFn: api.getStatistics,
  });

  const { events: recentEvents } = useWebSocket();

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold text-gray-900">Dashboard</h1>

      {/* Statistics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="Total Devices"
          value={stats?.total_devices ?? 0}
          color="blue"
        />
        <StatCard
          title="Trusted"
          value={stats?.trusted_devices ?? 0}
          color="green"
        />
        <StatCard
          title="Blocked"
          value={stats?.blocked_devices ?? 0}
          color="red"
        />
        <StatCard
          title="Events Today"
          value={stats?.events_today ?? 0}
          color="yellow"
        />
      </div>

      {/* Recent Events */}
      <div className="bg-white rounded-lg shadow">
        <div className="px-6 py-4 border-b">
          <h2 className="text-xl font-semibold">Recent Events</h2>
        </div>
        <div className="p-6">
          {recentEvents.length === 0 ? (
            <p className="text-gray-500">No recent events</p>
          ) : (
            <div className="space-y-4">
              {recentEvents.slice(0, 10).map((event, index) => (
                <div
                  key={index}
                  className="flex items-center justify-between border-b pb-2"
                >
                  <div>
                    <span className="font-medium">
                      {event.data.vid}:{event.data.pid}
                    </span>
                    <span className="ml-2 text-gray-500">
                      {event.data.product || 'Unknown'}
                    </span>
                  </div>
                  <span
                    className={`px-2 py-1 rounded text-sm ${
                      event.event === 'device.blocked'
                        ? 'bg-red-100 text-red-800'
                        : event.event === 'device.allowed'
                        ? 'bg-green-100 text-green-800'
                        : 'bg-yellow-100 text-yellow-800'
                    }`}
                  >
                    {event.data.verdict || event.event}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
