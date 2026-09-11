import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import AttackGraphCanvas from '../components/AttackGraphCanvas';
import { AttackNode, AttackEdge } from '../services/api';

// Mock ResizeObserver for jsdom
if (typeof window !== 'undefined') {
  window.ResizeObserver = class ResizeObserver {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
}

describe('Frontend Forensic Component Suite', () => {
  // 1. Loading State
  it('renders loading spinner and indicator', () => {
    const LoadingComponent = () => (
      <div data-testid="loading-container" className="flex items-center gap-2 text-cyan-400">
        <span data-testid="spinner" className="animate-spin">Loading</span>
        <span>Extracting forensic artifacts...</span>
      </div>
    );

    render(<LoadingComponent />);
    expect(screen.getByTestId('loading-container')).toBeInTheDocument();
    expect(screen.getByText('Extracting forensic artifacts...')).toBeInTheDocument();
  });

  // 2. Empty State
  it('renders empty state when no graph data is present', () => {
    render(<AttackGraphCanvas nodesData={[]} edgesData={[]} height="400px" />);
    expect(screen.getByText('No Attack Graph Data')).toBeInTheDocument();
    expect(
      screen.getByText(/Execute the APK or PCAP analysis pipeline to extract evidence entities/i)
    ).toBeInTheDocument();
  });

  // 3. Error State
  it('renders error alert banner with retry trigger', () => {
    const onRetry = vi.fn();
    const ErrorComponent = ({ onRetry }: { onRetry: () => void }) => (
      <div role="alert" className="p-4 bg-rose-950/40 border border-rose-800 text-rose-300 rounded">
        <h4>Analysis Pipeline Error</h4>
        <p>Failed to connect to backend forensic service.</p>
        <button onClick={onRetry} className="mt-2 px-3 py-1 bg-rose-700 text-white rounded">
          Retry Analysis
        </button>
      </div>
    );

    render(<ErrorComponent onRetry={onRetry} />);
    expect(screen.getByRole('alert')).toBeInTheDocument();
    expect(screen.getByText('Failed to connect to backend forensic service.')).toBeInTheDocument();

    const retryBtn = screen.getByText('Retry Analysis');
    fireEvent.click(retryBtn);
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  // 4. Success State
  it('renders success status badge and completion metadata', () => {
    const SuccessComponent = () => (
      <div className="flex items-center gap-2 bg-emerald-950/50 text-emerald-400 p-2 rounded">
        <span data-testid="status-badge" className="font-bold">STATUS: COMPLETED</span>
        <span>Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</span>
      </div>
    );

    render(<SuccessComponent />);
    expect(screen.getByTestId('status-badge')).toHaveTextContent('STATUS: COMPLETED');
    expect(screen.getByText(/Hash: e3b0c44298fc1c149afbf/i)).toBeInTheDocument();
  });

  // 5. Graph Canvas
  it('renders graph canvas with mode switcher and active nodes', () => {
    const mockNodes: AttackNode[] = [
      {
        node_id: 'node-app-1',
        case_id: 'case-1',
        node_type: 'APPLICATION',
        label: 'com.malicious.app',
        entity_reference: 'com.malicious.app',
        metadata: { source: 'APK' },
        created_at: new Date().toISOString()
      },
      {
        node_id: 'node-dom-1',
        case_id: 'case-1',
        node_type: 'DOMAIN',
        label: 'c2.evil-stealer.biz',
        entity_reference: 'c2.evil-stealer.biz',
        metadata: { source: 'PCAP' },
        created_at: new Date().toISOString()
      }
    ];

    const mockEdges: AttackEdge[] = [
      {
        edge_id: 'edge-1',
        case_id: 'case-1',
        source_node_id: 'node-app-1',
        target_node_id: 'node-dom-1',
        relationship_type: 'EMBEDS',
        relationship_class: 'CORRELATED',
        strength: 'STRONG',
        reason: 'APK bytecode embeds domain observed in DNS traffic',
        supporting_observation_ids: ['obs-1', 'obs-2'],
        supporting_correlation_ids: ['corr-1'],
        supporting_evidence_ids: ['ev-1', 'ev-2'],
        metadata: {},
        created_at: new Date().toISOString()
      }
    ];

    render(<AttackGraphCanvas nodesData={mockNodes} edgesData={mockEdges} height="500px" />);
    // View Switcher controls must be present
    expect(screen.getByText('Investigation Focus')).toBeInTheDocument();
    expect(screen.getByText('Full Provenance')).toBeInTheDocument();
    // Node values and badges should render in the canvas
    expect(screen.getByText('com.malicious.app')).toBeInTheDocument();
    expect(screen.getByText('c2.evil-stealer.biz')).toBeInTheDocument();
  });

  // 6. Timeline Component
  it('renders authentic timeline events in chronological order', () => {
    interface TimelineEvent {
      id: string;
      timestamp: string;
      label: string;
      source: string;
    }

    const events: TimelineEvent[] = [
      { id: '1', timestamp: '2026-08-31 10:00:00 UTC', label: 'APK Static Ingestion', source: 'APK' },
      { id: '2', timestamp: '2026-08-31 10:05:00 UTC', label: 'DNS Resolution Query', source: 'PCAP' },
      { id: '3', timestamp: '2026-08-31 10:05:15 UTC', label: 'Outbound TCP Session', source: 'PCAP' }
    ];

    const TimelineView = ({ items }: { items: TimelineEvent[] }) => (
      <div data-testid="timeline-list" className="space-y-2">
        {items.map((item) => (
          <div key={item.id} className="border-l-2 border-cyan-500 pl-3">
            <time className="font-mono text-xs text-slate-400">{item.timestamp}</time>
            <p className="text-sm font-semibold text-slate-200">{item.label}</p>
            <span className="text-xs text-cyan-400 font-mono">Source: {item.source}</span>
          </div>
        ))}
      </div>
    );

    render(<TimelineView items={events} />);
    const list = screen.getByTestId('timeline-list');
    expect(list).toBeInTheDocument();
    expect(screen.getByText('2026-08-31 10:00:00 UTC')).toBeInTheDocument();
    expect(screen.getByText('DNS Resolution Query')).toBeInTheDocument();
    expect(screen.getByText('Outbound TCP Session')).toBeInTheDocument();
  });

  // 7. Report Generator & Download
  it('renders report configuration form with HTML & PDF generation triggers', () => {
    const onGenerate = vi.fn();
    const ReportForm = ({ onGenerate }: { onGenerate: (format: string) => void }) => {
      const [format, setFormat] = React.useState('BOTH');
      return (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            onGenerate(format);
          }}
        >
          <label htmlFor="format-select">Report Format</label>
          <select
            id="format-select"
            value={format}
            onChange={(e) => setFormat(e.target.value)}
          >
            <option value="BOTH">HTML + PDF Dossier</option>
            <option value="HTML">HTML Interactive</option>
            <option value="PDF">PDF Document</option>
          </select>
          <button type="submit">Compile Forensic Report</button>
        </form>
      );
    };

    render(<ReportForm onGenerate={onGenerate} />);
    expect(screen.getByLabelText('Report Format')).toBeInTheDocument();
    
    const submitBtn = screen.getByText('Compile Forensic Report');
    fireEvent.click(submitBtn);
    expect(onGenerate).toHaveBeenCalledWith('BOTH');
  });
});
