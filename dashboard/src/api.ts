/**
 * API Client for USB Sentinel Backend
 *
 * Handles all REST API communication with the backend server.
 */

import axios, { AxiosInstance } from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';
const API_KEY = import.meta.env.VITE_API_KEY || '';

// Create axios instance with default config
const client: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
    ...(API_KEY && { 'X-API-Key': API_KEY }),
  },
});

// Request interceptor for logging
client.interceptors.request.use(
  (config) => {
    console.debug(`API Request: ${config.method?.toUpperCase()} ${config.url}`);
    return config;
  },
  (error) => {
    console.error('API Request Error:', error);
    return Promise.reject(error);
  }
);

// Response interceptor for error handling
client.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response) {
      console.error(`API Error ${error.response.status}:`, error.response.data);
    } else if (error.request) {
      console.error('API Network Error:', error.message);
    }
    return Promise.reject(error);
  }
);

// API functions
export const api = {
  // Health
  async getHealth() {
    const { data } = await client.get('/health');
    return data;
  },

  // Statistics
  async getStatistics() {
    const { data } = await client.get('/statistics');
    return data;
  },

  // Devices
  async getDevices(params?: {
    trust_level?: string | null;
    page?: number;
    page_size?: number;
  }) {
    const { data } = await client.get('/devices', { params });
    return data;
  },

  async getDevice(fingerprint: string) {
    const { data } = await client.get(`/devices/${fingerprint}`);
    return data;
  },

  async updateDeviceTrust(fingerprint: string, trust_level: string) {
    const { data } = await client.put(`/devices/${fingerprint}`, {
      trust_level,
    });
    return data;
  },

  async getDeviceStatistics(fingerprint: string) {
    const { data } = await client.get(`/devices/${fingerprint}/statistics`);
    return data;
  },

  // Events
  async getEvents(params?: {
    device_fingerprint?: string;
    event_type?: string | null;
    since?: string;
    page?: number;
    page_size?: number;
  }) {
    const { data } = await client.get('/events', { params });
    return data;
  },

  async getEvent(eventId: number) {
    const { data } = await client.get(`/events/${eventId}`);
    return data;
  },

  // Policy
  async getPolicy() {
    const { data } = await client.get('/policy');
    return data;
  },

  async updatePolicy(rules: any[]) {
    const { data } = await client.put('/policy', { rules });
    return data;
  },

  async validatePolicy(yaml: string) {
    // For now, just parse and validate on client side
    // In real implementation, send to backend
    const { data } = await client.post('/policy/validate', { yaml });
    return data;
  },

  async testPolicy(vid: string, pid: string) {
    const { data } = await client.post('/policy/test', { vid, pid });
    return data;
  },

  // Analysis
  async analyzeDevice(deviceInfo: {
    vid: string;
    pid: string;
    manufacturer?: string;
    product?: string;
  }) {
    const { data } = await client.post('/analyze', deviceInfo);
    return data;
  },

  // Export
  async exportData(
    what: 'devices' | 'events' | 'policy',
    format: 'json' | 'csv' = 'json'
  ) {
    const { data } = await client.get(`/export/${what}`, {
      params: { format },
    });
    return data;
  },
};

export default api;
