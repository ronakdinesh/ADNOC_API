import React, { useState, useEffect } from 'react';
import { 
  Box, 
  Heading, 
  Text, 
  SimpleGrid, 
  Card, 
  CardHeader, 
  CardBody, 
  Spinner, 
  Center, 
  Badge,
  Button,
  Flex,
  useToast
} from '@chakra-ui/react';
import { Link as RouterLink } from 'react-router-dom';
import axios from 'axios';

const Dashboard = () => {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const toast = useToast();

  useEffect(() => {
    const fetchIncidents = async () => {
      try {
        setLoading(true);
        const response = await axios.get('/api/incidents');
        
        if (response.data.error) {
          setError(response.data.error);
        } else {
          setIncidents(response.data.results || []);
        }
      } catch (err) {
        setError('Failed to fetch incidents. Please upload data or try again later.');
        console.error('Error fetching incidents:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchIncidents();
  }, []);

  const getSeverityColor = (severity) => {
    const severityMap = {
      'High': 'red',
      'Medium': 'orange',
      'Low': 'yellow',
      'Informational': 'blue'
    };
    return severityMap[severity] || 'gray';
  };

  const getStatusColor = (status) => {
    const statusMap = {
      'New': 'blue',
      'Active': 'purple',
      'Closed': 'green',
      'Resolved': 'green'
    };
    return statusMap[status] || 'gray';
  };

  return (
    <Box>
      <Flex justify="space-between" align="center" mb={6}>
        <Heading size="lg">Security Incidents</Heading>
        <Button 
          as={RouterLink} 
          to="/upload" 
          colorScheme="brand" 
          size="sm"
        >
          Upload New Data
        </Button>
      </Flex>

      {loading ? (
        <Center h="300px">
          <Spinner size="xl" color="brand.500" />
        </Center>
      ) : error ? (
        <Card p={4} bg="red.50" borderLeft="4px" borderColor="red.500">
          <CardBody>
            <Text>{error}</Text>
            <Button 
              as={RouterLink} 
              to="/upload" 
              mt={4} 
              colorScheme="brand"
            >
              Upload Incident Data
            </Button>
          </CardBody>
        </Card>
      ) : incidents.length === 0 ? (
        <Card p={4} bg="blue.50" borderLeft="4px" borderColor="blue.500">
          <CardBody>
            <Text>No incidents found. Please upload incident data to begin analysis.</Text>
            <Button 
              as={RouterLink} 
              to="/upload" 
              mt={4} 
              colorScheme="brand"
            >
              Upload Incident Data
            </Button>
          </CardBody>
        </Card>
      ) : (
        <SimpleGrid columns={{ base: 1, md: 2, lg: 3 }} spacing={6}>
          {incidents.map((incident) => (
            <Card 
              key={incident.incident_id} 
              boxShadow="md" 
              borderWidth="1px" 
              borderRadius="lg" 
              overflow="hidden"
              _hover={{ 
                transform: 'translateY(-5px)', 
                transition: 'transform 0.3s ease',
                boxShadow: 'lg' 
              }}
            >
              <CardHeader bg="gray.50" py={3} px={4}>
                <Flex justify="space-between" align="center">
                  <Heading size="md">Incident #{incident.incident_id}</Heading>
                  <Badge 
                    colorScheme={getSeverityColor(incident.analysis.current_severity)}
                  >
                    {incident.analysis.current_severity}
                  </Badge>
                </Flex>
              </CardHeader>
              <CardBody p={4}>
                <Text fontSize="sm" mb={2}>Type: {incident.analysis.incident_type}</Text>
                <Text fontSize="sm" mb={2}>
                  Status: <Badge colorScheme={getStatusColor(incident.analysis.current_status)}>
                    {incident.analysis.current_status}
                  </Badge>
                </Text>
                <Text fontSize="sm" mb={4}>
                  Updates: {incident.timeline.total_updates}
                </Text>
                
                <Flex justify="space-between" mt={4}>
                  <Button 
                    as={RouterLink} 
                    to={`/incidents/${incident.incident_id}`} 
                    size="sm"
                    variant="outline"
                    colorScheme="brand"
                  >
                    Details
                  </Button>
                  <Button 
                    as={RouterLink} 
                    to={`/incidents/${incident.incident_id}/timeline`} 
                    size="sm"
                    variant="outline"
                    colorScheme="purple"
                  >
                    Timeline
                  </Button>
                  <Button 
                    as={RouterLink} 
                    to={`/incidents/${incident.incident_id}/analysis`} 
                    size="sm"
                    variant="outline"
                    colorScheme="teal"
                  >
                    Analysis
                  </Button>
                </Flex>
              </CardBody>
            </Card>
          ))}
        </SimpleGrid>
      )}
    </Box>
  );
};

export default Dashboard; 