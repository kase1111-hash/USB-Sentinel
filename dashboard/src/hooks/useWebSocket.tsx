/**
 * WebSocket Hook for Real-time Events
 *
 * Manages WebSocket connection to USB Sentinel backend
 * for real-time device event streaming.
 */

import { useState, useEffect, useCallback, useRef } from 'react';

const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8000/api/events/stream';
const API_KEY = import.meta.env.VITE_API_KEY || '';

export interface WebSocketEvent {
  id: string;
  event: string;
  data: {
    fingerprint?: string;
    vid?: string;
    pid?: string;
    manufacturer?: string;
    product?: string;
    risk_score?: number;
    verdict?: string;
    [key: string]: any;
  };
  timestamp: string;
}

interface UseWebSocketOptions {
  autoConnect?: boolean;
  reconnectInterval?: number;
  maxReconnectAttempts?: number;
  onMessage?: (event: WebSocketEvent) => void;
  onConnect?: () => void;
  onDisconnect?: () => void;
  onError?: (error: Event) => void;
}

interface UseWebSocketReturn {
  events: WebSocketEvent[];
  isConnected: boolean;
  error: Error | null;
  connect: () => void;
  disconnect: () => void;
  clearEvents: () => void;
  subscribe: (eventTypes: string[]) => void;
  unsubscribe: (eventTypes: string[]) => void;
}

export function useWebSocket(options: UseWebSocketOptions = {}): UseWebSocketReturn {
  const {
    autoConnect = true,
    reconnectInterval = 5000,
    maxReconnectAttempts = 10,
    onMessage,
    onConnect,
    onDisconnect,
    onError,
  } = options;

  const [events, setEvents] = useState<WebSocketEvent[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectAttemptsRef = useRef(0);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      return;
    }

    try {
      // Build WebSocket URL with API key if available
      let url = WS_URL;
      if (API_KEY) {
        url += `?api_key=${encodeURIComponent(API_KEY)}`;
      }

      const ws = new WebSocket(url);

      ws.onopen = () => {
        console.log('WebSocket connected');
        setIsConnected(true);
        setError(null);
        reconnectAttemptsRef.current = 0;
        onConnect?.();
      };

      ws.onclose = (event) => {
        console.log('WebSocket disconnected', event.code, event.reason);
        setIsConnected(false);
        onDisconnect?.();

        // Attempt reconnection
        if (reconnectAttemptsRef.current < maxReconnectAttempts) {
          reconnectAttemptsRef.current++;
          console.log(
            `Reconnecting... attempt ${reconnectAttemptsRef.current}/${maxReconnectAttempts}`
          );
          reconnectTimeoutRef.current = setTimeout(connect, reconnectInterval);
        }
      };

      ws.onerror = (event) => {
        console.error('WebSocket error', event);
        setError(new Error('WebSocket connection error'));
        onError?.(event);
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data) as WebSocketEvent;
          setEvents((prev) => [data, ...prev].slice(0, 100)); // Keep last 100 events
          onMessage?.(data);
        } catch (e) {
          console.error('Failed to parse WebSocket message', e);
        }
      };

      wsRef.current = ws;
    } catch (e) {
      console.error('Failed to create WebSocket', e);
      setError(e instanceof Error ? e : new Error('Failed to connect'));
    }
  }, [
    onConnect,
    onDisconnect,
    onError,
    onMessage,
    maxReconnectAttempts,
    reconnectInterval,
  ]);

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }

    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }

    setIsConnected(false);
  }, []);

  const clearEvents = useCallback(() => {
    setEvents([]);
  }, []);

  const subscribe = useCallback((eventTypes: string[]) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(
        JSON.stringify({
          event: 'subscribe',
          data: { events: eventTypes },
        })
      );
    }
  }, []);

  const unsubscribe = useCallback((eventTypes: string[]) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(
        JSON.stringify({
          event: 'unsubscribe',
          data: { events: eventTypes },
        })
      );
    }
  }, []);

  // Auto-connect on mount
  useEffect(() => {
    if (autoConnect) {
      connect();
    }

    return () => {
      disconnect();
    };
  }, [autoConnect, connect, disconnect]);

  return {
    events,
    isConnected,
    error,
    connect,
    disconnect,
    clearEvents,
    subscribe,
    unsubscribe,
  };
}

export default useWebSocket;
