/**
 * EventFeed - Real-time event log
 *
 * Shows USB device events with filtering and real-time updates.
 */

import { useState, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useWebSocket } from '../hooks/useWebSocket';
import { api } from '../api';

interface Event {
  id: number;
  timestamp: string;
  device_fingerprint: string;
  event_type: string;
  policy_rule: string | null;
  llm_analysis: string | null;
  risk_score: number | null;
  verdict: string | null;
}

interface EventListResponse {
  items: Event[];
  total: number;
  page: number;
  page_size: number;
}

function EventRow({ event }: { event: Event }) {
  const [expanded, setExpanded] = useState(false);

  const verdictColors = {
    allowed: 'bg-green-100 text-green-800',
    blocked: 'bg-red-100 text-red-800',
    sandboxed: 'bg-yellow-100 text-yellow-800',
    review: 'bg-blue-100 text-blue-800',
  };

  const riskColor =
    event.risk_score === null
      ? 'text-gray-400'
      : event.risk_score >= 75
      ? 'text-red-600'
      : event.risk_score >= 50
      ? 'text-yellow-600'
      : 'text-green-600';

  return (
    <div className="border-b hover:bg-gray-50">
      <div
        className="flex items-center justify-between p-4 cursor-pointer"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center space-x-4">
          <span className="text-gray-500 text-sm w-36">
            {new Date(event.timestamp).toLocaleString()}
          </span>
          <span className="font-mono text-sm">
            {event.device_fingerprint.substring(0, 12)}...
          </span>
          <span className="text-sm">{event.event_type}</span>
        </div>
        <div className="flex items-center space-x-4">
          <span className={`text-sm font-medium ${riskColor}`}>
            {event.risk_score !== null ? `${event.risk_score}%` : '-'}
          </span>
          {event.verdict && (
            <span
              className={`px-2 py-1 rounded text-sm ${
                verdictColors[event.verdict] || 'bg-gray-100'
              }`}
            >
              {event.verdict}
            </span>
          )}
          <span className="text-gray-400">{expanded ? '▲' : '▼'}</span>
        </div>
      </div>

      {expanded && (
        <div className="px-4 pb-4 bg-gray-50">
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-gray-500">Device:</span>
              <span className="ml-2 font-mono">{event.device_fingerprint}</span>
            </div>
            <div>
              <span className="text-gray-500">Policy Rule:</span>
              <span className="ml-2">{event.policy_rule || 'None'}</span>
            </div>
          </div>
          {event.llm_analysis && (
            <div className="mt-4">
              <span className="text-gray-500 block mb-2">LLM Analysis:</span>
              <div className="bg-white p-3 rounded border text-sm">
                {event.llm_analysis}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export function EventFeed() {
  const [typeFilter, setTypeFilter] = useState<string | null>(null);
  const [page, setPage] = useState(1);

  const { data, isLoading } = useQuery<EventListResponse>({
    queryKey: ['events', typeFilter, page],
    queryFn: () =>
      api.getEvents({
        event_type: typeFilter,
        page,
        page_size: 20,
      }),
  });

  const { events: liveEvents } = useWebSocket();

  // Combine live events with loaded events
  const allEvents = [
    ...liveEvents.map((e, i) => ({
      id: -i - 1,
      timestamp: e.timestamp,
      device_fingerprint: e.data.fingerprint || 'unknown',
      event_type: e.event.replace('device.', ''),
      policy_rule: null,
      llm_analysis: null,
      risk_score: e.data.risk_score,
      verdict: e.data.verdict,
    })),
    ...(data?.items || []),
  ];

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold text-gray-900">Event Log</h1>
        <div className="flex space-x-2">
          {['all', 'connect', 'allowed', 'blocked'].map((type) => (
            <button
              key={type}
              onClick={() => setTypeFilter(type === 'all' ? null : type)}
              className={`px-4 py-2 rounded ${
                (typeFilter === type || (type === 'all' && !typeFilter))
                  ? 'bg-blue-500 text-white'
                  : 'bg-gray-200 hover:bg-gray-300'
              }`}
            >
              {type.charAt(0).toUpperCase() + type.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {liveEvents.length > 0 && (
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-3 text-sm text-blue-700">
          {liveEvents.length} new events received in real-time
        </div>
      )}

      <div className="bg-white rounded-lg shadow">
        {isLoading ? (
          <div className="flex items-center justify-center h-64">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500" />
          </div>
        ) : allEvents.length === 0 ? (
          <div className="text-center text-gray-500 py-12">No events found</div>
        ) : (
          <div>
            {allEvents.map((event) => (
              <EventRow key={event.id} event={event} />
            ))}
          </div>
        )}
      </div>

      {/* Pagination */}
      {data && data.total > 20 && (
        <div className="flex justify-center space-x-2">
          <button
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page === 1}
            className="px-4 py-2 bg-gray-200 rounded disabled:opacity-50"
          >
            Previous
          </button>
          <span className="px-4 py-2">
            Page {page} of {Math.ceil(data.total / 20)}
          </span>
          <button
            onClick={() => setPage((p) => p + 1)}
            disabled={page >= Math.ceil(data.total / 20)}
            className="px-4 py-2 bg-gray-200 rounded disabled:opacity-50"
          >
            Next
          </button>
        </div>
      )}
    </div>
  );
}
