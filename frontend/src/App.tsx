import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import Investigations from './pages/Investigations';
import InvestigationDetails from './pages/InvestigationDetails';
import Analysis from './pages/Analysis';
import AttackGraph from './pages/AttackGraph';
import Reports from './pages/Reports';

const App: React.FC = () => {
  return (
    <Router>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/investigations" element={<Investigations />} />
          <Route path="/investigations/:id" element={<InvestigationDetails />} />
          <Route path="/analysis" element={<Analysis />} />
          <Route path="/attack-graph" element={<AttackGraph />} />
          <Route path="/reports" element={<Reports />} />
        </Routes>
      </Layout>
    </Router>
  );
};

export default App;
