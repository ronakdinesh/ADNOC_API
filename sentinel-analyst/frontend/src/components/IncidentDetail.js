import React, { useState, useEffect } from 'react';
import { 
  Box, 
  Heading, 
  Text, 
  Flex, 
  Badge, 
  Spinner, 
  Card,
  CardHeader,
  CardBody,
  SimpleGrid,
  Divider,
  Stack,
  Button,
  Stat,
  StatLabel,
  StatNumber,
  StatHelpText,
  Tab,
  TabList,
  TabPanel,
  TabPanels,
  Tabs,
  useColorModeValue
} from '@chakra-ui/react';
import { useParams, Link } from 'react-router-dom';
import axios from 'axios';

const IncidentDetail = () => {
  const { incidentId } = useParams();
  const [incident, setIncident] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  const cardBg = useColorModeValue('white', 'gray.800');
  
  useEffect(() => {
    const fetchIncidentData = async () => {
      try {
        setLoading(true);
        const response = await axios.get(`/api/incidents?incident_id=${incidentId}`);
        
        if (response.data.error) {
          setError(response.data.error);
        } else if (!response.data.results || response.data.results.length === 0) {
          setError(`Incident #${incidentId} not found`);
        } else {
          setIncident(response.data.results[0]);
        }
      } catch (err) {
        setError(`Error fetching incident data: ${err.message}`);
        console.error('Error fetching incident data:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchIncidentData();
  }, [incidentId]);

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

  if (loading) {
    return (
      <Flex justify="center" align="center" height="300px">
        <Spinner size="xl" color="brand.500" />
      </Flex>
    );
  }

  if (error) {
    return (
      <Box>
        <Heading size="lg" mb={4}>Incident Details</Heading>
        <Card bg="red.50" borderLeft="4px" borderColor="red.500">
          <CardBody>
            <Text>{error}</Text>
            <Button as={Link} to="/" mt={4} colorScheme="brand">
              Return to Dashboard
            </Button>
          </CardBody>
        </Card>
      </Box>
    );
  }

  const analysis = incident.analysis;
  const timeline = incident.timeline;

  return (
    <Box>
      <Flex justify="space-between" align="center" mb={6}>
        <Heading size="lg">Incident #{incidentId}</Heading>
        <Flex gap={2}>
          <Badge colorScheme={getSeverityColor(analysis.current_severity)} fontSize="md" py={1} px={2}>
            {analysis.current_severity}
          </Badge>
          <Badge colorScheme={getStatusColor(analysis.current_status)} fontSize="md" py={1} px={2}>
            {analysis.current_status}
          </Badge>
        </Flex>
      </Flex>

      <SimpleGrid columns={{ base: 1, md: 3 }} spacing={6} mb={6}>
        <Card bg={cardBg} boxShadow="md" borderRadius="lg">
          <CardBody>
            <Stat>
              <StatLabel>First Detected</StatLabel>
              <StatNumber fontSize="md">{timeline.first_detected}</StatNumber>
              <StatHelpText>Initial: {timeline.first_severity} severity</StatHelpText>
            </Stat>
          </CardBody>
        </Card>
        
        <Card bg={cardBg} boxShadow="md" borderRadius="lg">
          <CardBody>
            <Stat>
              <StatLabel>Type</StatLabel>
              <StatNumber fontSize="md">{analysis.incident_type}</StatNumber>
              <StatHelpText>Tenant: {analysis.tenant_id}</StatHelpText>
            </Stat>
          </CardBody>
        </Card>
        
        <Card bg={cardBg} boxShadow="md" borderRadius="lg">
          <CardBody>
            <Stat>
              <StatLabel>Updates</StatLabel>
              <StatNumber fontSize="md">{timeline.total_updates}</StatNumber>
              <StatHelpText>Last: {analysis.last_updated}</StatHelpText>
            </Stat>
          </CardBody>
        </Card>
      </SimpleGrid>

      <Tabs variant="enclosed" colorScheme="brand" mb={6}>
        <TabList>
          <Tab>Overview</Tab>
          <Tab>Timeline</Tab>
          <Tab>Analysis</Tab>
          <Tab>Entities</Tab>
        </TabList>
        
        <TabPanels>
          <TabPanel>
            <Card bg={cardBg} boxShadow="md" borderRadius="lg">
              <CardHeader>
                <Heading size="md">Incident Summary</Heading>
              </CardHeader>
              <CardBody>
                <Text>{timeline.summary}</Text>
                
                <Divider my={4} />
                
                <Stack spacing={3}>
                  <Heading size="sm">Key Points</Heading>
                  {analysis.analysis.key_points ? (
                    analysis.analysis.key_points.map((point, idx) => (
                      <Text key={idx} fontSize="sm">• {point}</Text>
                    ))
                  ) : (
                    <Text>No key points available</Text>
                  )}
                </Stack>
              </CardBody>
            </Card>
          </TabPanel>
          
          <TabPanel>
            <Card bg={cardBg} boxShadow="md" borderRadius="lg">
              <CardHeader>
                <Heading size="md">Incident Timeline</Heading>
              </CardHeader>
              <CardBody>
                <Stack spacing={4} divider={<Divider />}>
                  {timeline.key_milestones.map((milestone, idx) => (
                    <Box key={idx}>
                      <Text fontWeight="bold" mb={1}>{milestone.timestamp}</Text>
                      {milestone.changes.map((change, changeIdx) => (
                        <Box key={changeIdx} ml={4} mb={1}>
                          {change.action ? (
                            <>
                              <Text fontSize="sm">• {change.action}</Text>
                              {change.summary && (
                                <Text fontSize="sm" color="gray.600" ml={4}>{change.summary}</Text>
                              )}
                            </>
                          ) : (
                            <Text fontSize="sm">• {change.field} changed: {change.from} → {change.to}</Text>
                          )}
                        </Box>
                      ))}
                    </Box>
                  ))}
                </Stack>
                
                <Button 
                  as={Link} 
                  to={`/incidents/${incidentId}/timeline`}
                  mt={4}
                  colorScheme="brand"
                  variant="outline"
                >
                  View Detailed Timeline
                </Button>
              </CardBody>
            </Card>
          </TabPanel>
          
          <TabPanel>
            <Card bg={cardBg} boxShadow="md" borderRadius="lg">
              <CardHeader>
                <Heading size="md">Incident Analysis</Heading>
              </CardHeader>
              <CardBody>
                <Text fontWeight="bold" mb={2}>Summary</Text>
                <Text mb={4}>{analysis.analysis.summary}</Text>
                
                <Text fontWeight="bold" mb={2}>Description</Text>
                <Text mb={4}>{analysis.analysis.description}</Text>
                
                <Divider my={4} />
                
                <Stack spacing={3}>
                  <Heading size="sm">Recommended Actions</Heading>
                  {analysis.analysis.recommended_actions ? (
                    analysis.analysis.recommended_actions.map((action, idx) => (
                      <Text key={idx} fontSize="sm">• {action}</Text>
                    ))
                  ) : (
                    <Text>No recommended actions available</Text>
                  )}
                </Stack>
                
                <Button 
                  as={Link} 
                  to={`/incidents/${incidentId}/analysis`}
                  mt={4}
                  colorScheme="brand"
                  variant="outline"
                >
                  View Full Analysis
                </Button>
              </CardBody>
            </Card>
          </TabPanel>
          
          <TabPanel>
            <Card bg={cardBg} boxShadow="md" borderRadius="lg">
              <CardHeader>
                <Heading size="md">Entities Found</Heading>
              </CardHeader>
              <CardBody>
                <SimpleGrid columns={{ base: 1, md: 2 }} spacing={6}>
                  <Box>
                    <Heading size="sm" mb={3}>IP Addresses ({analysis.entities.ips.length})</Heading>
                    {analysis.entities.ips.length > 0 ? (
                      analysis.entities.ips.map((ip, idx) => (
                        <Badge key={idx} m={1} p={1}>{ip}</Badge>
                      ))
                    ) : (
                      <Text>No IP addresses found</Text>
                    )}
                  </Box>
                  
                  <Box>
                    <Heading size="sm" mb={3}>Domains ({analysis.entities.domains.length})</Heading>
                    {analysis.entities.domains.length > 0 ? (
                      analysis.entities.domains.map((domain, idx) => (
                        <Badge key={idx} m={1} p={1} variant="outline">{domain}</Badge>
                      ))
                    ) : (
                      <Text>No domains found</Text>
                    )}
                  </Box>
                </SimpleGrid>
              </CardBody>
            </Card>
          </TabPanel>
        </TabPanels>
      </Tabs>
      
      <Flex justify="space-between">
        <Button as={Link} to="/" colorScheme="gray">
          Back to Dashboard
        </Button>
        <Flex gap={2}>
          <Button as={Link} to={`/incidents/${incidentId}/timeline`} colorScheme="purple" variant="outline">
            View Timeline
          </Button>
          <Button as={Link} to={`/incidents/${incidentId}/analysis`} colorScheme="teal" variant="outline">
            View Analysis
          </Button>
        </Flex>
      </Flex>
    </Box>
  );
};

export default IncidentDetail; 