import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { Box } from '@chakra-ui/react';

// Import components
import Dashboard from './components/Dashboard';
import Navbar from './components/Navbar';
import IncidentDetail from './components/IncidentDetail';
import IncidentTimeline from './components/IncidentTimeline';
import IncidentAnalysis from './components/IncidentAnalysis';
import UploadData from './components/UploadData';

function App() {
  return (
    <Router>
      <Box minH="100vh" bg="gray.50">
        <Navbar />
        <Box as="main" p={4} maxWidth="1400px" mx="auto">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/incidents/:incidentId" element={<IncidentDetail />} />
            <Route path="/incidents/:incidentId/timeline" element={<IncidentTimeline />} />
            <Route path="/incidents/:incidentId/analysis" element={<IncidentAnalysis />} />
            <Route path="/upload" element={<UploadData />} />
          </Routes>
        </Box>
      </Box>
    </Router>
  );
}

export default App; 