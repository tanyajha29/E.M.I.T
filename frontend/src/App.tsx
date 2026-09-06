import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/Layout';
import { ProtectedRoute } from './components/ProtectedRoute';
import { UserProvider } from './context/UserContext';

// Public Auth & Landing Pages
import LandingPage from './pages/LandingPage';
import SignIn from './pages/SignIn';
import SignUp from './pages/SignUp';

// Protected DFIR Workbench Pages
import Dashboard from './pages/Dashboard';
import Investigations from './pages/Investigations';
import InvestigationDetails from './pages/InvestigationDetails';
import Analysis from './pages/Analysis';
import AttackGraph from './pages/AttackGraph';
import Reports from './pages/Reports';

const App: React.FC = () => {
  return (
    <UserProvider>
      <Router>
        <Routes>
          {/* Public Routes */}
          <Route path="/" element={<LandingPage />} />
          <Route path="/signin" element={<SignIn />} />
          <Route path="/signup" element={<SignUp />} />

          {/* Protected DFIR Workbench Routes */}
          <Route
            path="/dashboard"
            element={
              <ProtectedRoute>
                <Layout>
                  <Dashboard />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/investigations"
            element={
              <ProtectedRoute>
                <Layout>
                  <Investigations />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/investigations/:id"
            element={
              <ProtectedRoute>
                <Layout>
                  <InvestigationDetails />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/analysis"
            element={
              <ProtectedRoute>
                <Layout>
                  <Analysis />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/attack-graph"
            element={
              <ProtectedRoute>
                <Layout>
                  <AttackGraph />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/reports"
            element={
              <ProtectedRoute>
                <Layout>
                  <Reports />
                </Layout>
              </ProtectedRoute>
            }
          />

          {/* Fallback to Landing */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Router>
    </UserProvider>
  );
};

export default App;
