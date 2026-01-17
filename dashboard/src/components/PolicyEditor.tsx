/**
 * PolicyEditor - Policy rule management
 *
 * YAML-based policy editor with validation and testing.
 */

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '../api';

interface PolicyRule {
  match: Record<string, any> | string;
  action: string;
  comment: string;
  priority: number;
}

interface PolicyResponse {
  rules: PolicyRule[];
  rule_count: number;
  last_modified: string | null;
}

interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

function RuleCard({
  rule,
  index,
}: {
  rule: PolicyRule;
  index: number;
}) {
  const actionColors = {
    allow: 'bg-green-100 text-green-800 border-green-300',
    block: 'bg-red-100 text-red-800 border-red-300',
    review: 'bg-yellow-100 text-yellow-800 border-yellow-300',
  };

  const matchDisplay =
    typeof rule.match === 'string'
      ? rule.match
      : JSON.stringify(rule.match, null, 2);

  return (
    <div className={`border rounded-lg p-4 ${actionColors[rule.action] || 'border-gray-300'}`}>
      <div className="flex justify-between items-start">
        <div>
          <span className="text-gray-500 text-sm">Rule {index + 1}</span>
          <div className="flex items-center space-x-2 mt-1">
            <span
              className={`px-2 py-1 rounded text-sm font-medium ${
                actionColors[rule.action] || 'bg-gray-100'
              }`}
            >
              {rule.action.toUpperCase()}
            </span>
            {rule.comment && (
              <span className="text-gray-600">{rule.comment}</span>
            )}
          </div>
        </div>
      </div>
      <div className="mt-3">
        <span className="text-gray-500 text-sm">Match:</span>
        <pre className="bg-white bg-opacity-50 p-2 rounded text-sm mt-1 overflow-x-auto">
          {matchDisplay}
        </pre>
      </div>
    </div>
  );
}

export function PolicyEditor() {
  const [yamlContent, setYamlContent] = useState('');
  const [testVid, setTestVid] = useState('');
  const [testPid, setTestPid] = useState('');
  const [testResult, setTestResult] = useState<string | null>(null);
  const queryClient = useQueryClient();

  const { data: policy, isLoading } = useQuery<PolicyResponse>({
    queryKey: ['policy'],
    queryFn: api.getPolicy,
  });

  const validateMutation = useMutation<ValidationResult, Error, string>({
    mutationFn: (yaml: string) => api.validatePolicy(yaml),
  });

  const testPolicyMutation = useMutation({
    mutationFn: ({ vid, pid }: { vid: string; pid: string }) =>
      api.testPolicy(vid, pid),
    onSuccess: (result) => {
      setTestResult(`Action: ${result.action.toUpperCase()}\nRule: ${result.rule || 'Default'}`);
    },
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold text-gray-900">Policy Editor</h1>
        <div className="text-gray-500">
          {policy?.rule_count ?? 0} rules configured
        </div>
      </div>

      {/* Current Rules */}
      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-xl font-semibold mb-4">Current Rules</h2>
        <div className="space-y-4">
          {policy?.rules.map((rule, index) => (
            <RuleCard key={index} rule={rule} index={index} />
          ))}
          {(!policy || policy.rules.length === 0) && (
            <p className="text-gray-500">No rules configured</p>
          )}
        </div>
      </div>

      {/* Policy Tester */}
      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-xl font-semibold mb-4">Test Policy</h2>
        <div className="flex space-x-4">
          <div>
            <label className="block text-sm text-gray-600 mb-1">Vendor ID</label>
            <input
              type="text"
              value={testVid}
              onChange={(e) => setTestVid(e.target.value)}
              placeholder="e.g., 046d"
              className="border rounded px-3 py-2 w-32"
              maxLength={4}
            />
          </div>
          <div>
            <label className="block text-sm text-gray-600 mb-1">Product ID</label>
            <input
              type="text"
              value={testPid}
              onChange={(e) => setTestPid(e.target.value)}
              placeholder="e.g., c534"
              className="border rounded px-3 py-2 w-32"
              maxLength={4}
            />
          </div>
          <div className="flex items-end">
            <button
              onClick={() => testPolicyMutation.mutate({ vid: testVid, pid: testPid })}
              disabled={!testVid || !testPid || testPolicyMutation.isPending}
              className="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600 disabled:opacity-50"
            >
              {testPolicyMutation.isPending ? 'Testing...' : 'Test'}
            </button>
          </div>
        </div>
        {testResult && (
          <pre className="mt-4 bg-gray-50 p-4 rounded text-sm">{testResult}</pre>
        )}
      </div>

      {/* YAML Editor */}
      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-xl font-semibold mb-4">Edit Policy (YAML)</h2>
        <textarea
          value={yamlContent}
          onChange={(e) => setYamlContent(e.target.value)}
          placeholder="Paste your policy YAML here..."
          className="w-full h-64 font-mono text-sm border rounded p-4"
        />
        <div className="flex space-x-4 mt-4">
          <button
            onClick={() => validateMutation.mutate(yamlContent)}
            disabled={!yamlContent || validateMutation.isPending}
            className="bg-gray-200 px-4 py-2 rounded hover:bg-gray-300 disabled:opacity-50"
          >
            Validate
          </button>
          <button
            disabled={!yamlContent}
            className="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600 disabled:opacity-50"
          >
            Save Policy
          </button>
        </div>

        {validateMutation.data && (
          <div
            className={`mt-4 p-4 rounded ${
              validateMutation.data.valid
                ? 'bg-green-50 text-green-700'
                : 'bg-red-50 text-red-700'
            }`}
          >
            {validateMutation.data.valid ? (
              <p>Policy is valid</p>
            ) : (
              <div>
                <p className="font-medium">Validation errors:</p>
                <ul className="list-disc list-inside mt-2">
                  {validateMutation.data.errors.map((err, i) => (
                    <li key={i}>{err}</li>
                  ))}
                </ul>
              </div>
            )}
            {validateMutation.data.warnings.length > 0 && (
              <div className="mt-2 text-yellow-700">
                <p className="font-medium">Warnings:</p>
                <ul className="list-disc list-inside">
                  {validateMutation.data.warnings.map((warn, i) => (
                    <li key={i}>{warn}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
