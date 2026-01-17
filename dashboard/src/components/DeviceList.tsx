/**
 * DeviceList - Device inventory management
 *
 * Lists all known USB devices with trust management capabilities.
 */

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '../api';

interface Device {
  id: number;
  fingerprint: string;
  vid: string;
  pid: string;
  manufacturer: string | null;
  product: string | null;
  trust_level: string;
  first_seen: string;
  last_seen: string | null;
  event_count: number;
}

interface DeviceListResponse {
  items: Device[];
  total: number;
  page: number;
  page_size: number;
}

function TrustBadge({ level }: { level: string }) {
  const colors = {
    trusted: 'bg-green-100 text-green-800',
    blocked: 'bg-red-100 text-red-800',
    unknown: 'bg-gray-100 text-gray-800',
    review: 'bg-yellow-100 text-yellow-800',
  };

  return (
    <span className={`px-2 py-1 rounded text-sm ${colors[level] || colors.unknown}`}>
      {level}
    </span>
  );
}

function DeviceCard({
  device,
  onTrustChange,
}: {
  device: Device;
  onTrustChange: (fingerprint: string, level: string) => void;
}) {
  const [showActions, setShowActions] = useState(false);

  return (
    <div className="bg-white rounded-lg shadow p-4 hover:shadow-md transition-shadow">
      <div className="flex justify-between items-start">
        <div>
          <div className="flex items-center space-x-2">
            <span className="font-mono text-lg font-bold">
              {device.vid}:{device.pid}
            </span>
            <TrustBadge level={device.trust_level} />
          </div>
          <p className="text-gray-600 mt-1">
            {device.product || device.manufacturer || 'Unknown Device'}
          </p>
          <p className="text-gray-400 text-sm mt-1 font-mono">
            {device.fingerprint.substring(0, 16)}...
          </p>
        </div>
        <div className="relative">
          <button
            onClick={() => setShowActions(!showActions)}
            className="p-2 hover:bg-gray-100 rounded"
          >
            <span>...</span>
          </button>
          {showActions && (
            <div className="absolute right-0 mt-2 w-48 bg-white rounded-lg shadow-lg border z-10">
              <button
                onClick={() => {
                  onTrustChange(device.fingerprint, 'trusted');
                  setShowActions(false);
                }}
                className="block w-full text-left px-4 py-2 hover:bg-green-50 text-green-700"
              >
                Mark Trusted
              </button>
              <button
                onClick={() => {
                  onTrustChange(device.fingerprint, 'blocked');
                  setShowActions(false);
                }}
                className="block w-full text-left px-4 py-2 hover:bg-red-50 text-red-700"
              >
                Block Device
              </button>
              <button
                onClick={() => {
                  onTrustChange(device.fingerprint, 'unknown');
                  setShowActions(false);
                }}
                className="block w-full text-left px-4 py-2 hover:bg-gray-50"
              >
                Reset to Unknown
              </button>
            </div>
          )}
        </div>
      </div>
      <div className="mt-4 flex justify-between text-sm text-gray-500">
        <span>First seen: {new Date(device.first_seen).toLocaleDateString()}</span>
        <span>{device.event_count} events</span>
      </div>
    </div>
  );
}

export function DeviceList() {
  const [filter, setFilter] = useState<string | null>(null);
  const queryClient = useQueryClient();

  const { data, isLoading, error } = useQuery<DeviceListResponse>({
    queryKey: ['devices', filter],
    queryFn: () => api.getDevices({ trust_level: filter }),
  });

  const updateTrustMutation = useMutation({
    mutationFn: ({ fingerprint, level }: { fingerprint: string; level: string }) =>
      api.updateDeviceTrust(fingerprint, level),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['devices'] });
    },
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 text-red-700 p-4 rounded-lg">
        Error loading devices: {error.message}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold text-gray-900">Device Inventory</h1>
        <div className="flex space-x-2">
          {['all', 'trusted', 'blocked', 'unknown'].map((level) => (
            <button
              key={level}
              onClick={() => setFilter(level === 'all' ? null : level)}
              className={`px-4 py-2 rounded ${
                (filter === level || (level === 'all' && !filter))
                  ? 'bg-blue-500 text-white'
                  : 'bg-gray-200 hover:bg-gray-300'
              }`}
            >
              {level.charAt(0).toUpperCase() + level.slice(1)}
            </button>
          ))}
        </div>
      </div>

      <div className="text-gray-500">
        {data?.total ?? 0} devices total
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {data?.items.map((device) => (
          <DeviceCard
            key={device.fingerprint}
            device={device}
            onTrustChange={(fp, level) =>
              updateTrustMutation.mutate({ fingerprint: fp, level })
            }
          />
        ))}
      </div>

      {data?.items.length === 0 && (
        <div className="text-center text-gray-500 py-12">
          No devices found
        </div>
      )}
    </div>
  );
}
