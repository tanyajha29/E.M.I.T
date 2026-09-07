import { Component, ErrorInfo, ReactNode } from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

interface Props {
  children: ReactNode;
  fallbackTitle?: string;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Uncaught error in component tree:', error, errorInfo);
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null });
    window.location.reload();
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-[400px] flex items-center justify-center p-6 font-mono text-white">
          <div className="w-full max-w-lg bg-[#101010] border border-[#FF3333]/50 rounded-lg p-6 space-y-4 shadow-[0_0_30px_rgba(255,51,51,0.15)]">
            <div className="flex items-center gap-3 border-b border-[#222222] pb-3">
              <div className="p-2 rounded bg-[#FF3333]/10 border border-[#FF3333]/30 text-[#FF3333]">
                <AlertTriangle className="h-5 w-5" />
              </div>
              <div>
                <h3 className="text-sm font-bold uppercase tracking-wider text-white">
                  {this.props.fallbackTitle || 'Forensic Component Render Exception'}
                </h3>
                <span className="text-[10px] text-[#AAAAAA]">RUNTIME ERROR CAPTURED</span>
              </div>
            </div>

            <div className="bg-[#050505] p-3.5 rounded border border-[#222222] text-xs space-y-2">
              <p className="text-[#AAAAAA]">
                An unexpected error occurred while rendering this view. State has been contained.
              </p>
              {this.state.error && (
                <pre className="text-[10px] text-[#FF6666] font-mono whitespace-pre-wrap break-all overflow-x-auto max-h-32 p-2 bg-[#0A0A0A] rounded border border-[#FF3333]/20">
                  {this.state.error.message || String(this.state.error)}
                </pre>
              )}
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={this.handleReset}
                className="inline-flex items-center gap-2 px-4 py-2 bg-[#00FF00] hover:bg-[#00DD00] text-black rounded text-xs font-bold uppercase tracking-wider transition-colors shadow-[0_0_12px_rgba(0,255,0,0.3)]"
              >
                <RefreshCw className="h-3.5 w-3.5" />
                <span>Reload Workbench</span>
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
